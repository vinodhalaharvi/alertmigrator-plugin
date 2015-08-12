import ApiController
import org.hyperic.hq.hqapi1.ErrorCode
import org.hyperic.hq.appdef.shared.AppdefEntityID
import org.hyperic.hq.appdef.shared.AppdefUtil
import org.hyperic.hq.authz.shared.AuthzConstants
import org.hyperic.hq.authz.shared.PermissionException
import org.hyperic.hq.authz.shared.ResourceEdgeCreateException
import org.hyperic.hq.appdef.shared.AppdefEntityValue
import org.hyperic.hq.appdef.shared.ServiceManager
import org.hyperic.hq.appdef.shared.ServerManager
import org.hyperic.hq.appdef.shared.PlatformManager
import org.hyperic.hq.authz.shared.ResourceManager
import org.hyperic.hq.authz.server.session.Resource
import org.hyperic.hq.context.Bootstrap
import org.hyperic.hq.common.VetoException
import org.hyperic.hq.events.shared.AlertConditionValue
import org.hyperic.hq.events.shared.AlertDefinitionManager
import org.hyperic.hq.events.shared.AlertDefinitionValue
import org.hyperic.hq.events.AlertSeverity
import org.hyperic.hq.appdef.shared.AppdefEntityTypeID

//AlertDefinitionContoller class imports
import org.hyperic.hq.auth.shared.SessionManager
import org.hyperic.hq.bizapp.shared.EventsBoss;
import org.hyperic.hq.events.EventConstants
import org.hyperic.hq.events.shared.ActionValue
import org.hyperic.hq.measurement.shared.ResourceLogEvent
import org.hyperic.hq.measurement.shared.MeasurementManager;
import org.hyperic.util.config.ConfigResponse
import org.hyperic.hq.appdef.server.session.Platform
import org.hyperic.hq.appdef.server.session.Server
import org.hyperic.hq.appdef.server.session.Service


class ResourceController extends ApiController {

    private static final String PROP_FQDN        = "fqdn"
    private static final String PROP_INSTALLPATH = "installPath"
    private static final String PROP_AIIDENIFIER = "autoIdentifier"
    private static final String PROP_AGENT_ID    = "agentId"

    private static platMan = Bootstrap.getBean(PlatformManager.class)
    private static svrMan = Bootstrap.getBean(ServerManager.class)
    private static svcMan = Bootstrap.getBean(ServiceManager.class)
    private static resMan = Bootstrap.getBean(ResourceManager.class)
    private aMan = Bootstrap.getBean(AlertDefinitionManager.class)
    private eventBoss   = Bootstrap.getBean(EventsBoss.class)
    private mMan        = Bootstrap.getBean(MeasurementManager.class)

    private EMAIL_NOTIFY_TYPE = [1:"email", 2:"users", 3:"roles"]


    private toPlatform(Resource r) {
        platMan.findPlatformById(r.instanceId)
    }

    private toServer(Resource r) {
        svrMan.findServerById(r.instanceId)
    }

    private toService(Resource r) {
        svcMan.findServiceById(r.instanceId)
    }

    /**
     * Seems as though the measurementId column for alert conditions can
     * equal 0 (or something else not found in the DB?)
     *
     * We safely avoid any problems by returning 'Unknown' for templates
     * we can't find.
     */
    private getTemplate(int mid, typeBased) {
        if (typeBased) {
            try {
                return metricHelper.findTemplateById(mid)
            } catch (Exception e) {
                log.warn("HQPI WARN: Lookup of template id=${mid} failed", e)
            }
        }
        else {
            return mMan.getMeasurement(mid)?.template
        }
        return null
    }


    private checkRequiredAttributes(name, xml, attrs) {
        for (attr in attrs) {
            if (xml."@${attr}" == null) {
                return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                     "Required attribute '" + attr +
                                     "' not given for " + name)
            }
        }
        return null
    }

    private Closure getResourceXML(user, r, boolean verbose, boolean children) {
        { doc ->
            def appdefRes = null
            def isPlatform = r.isPlatform()
            if (isPlatform) {
                appdefRes = toPlatform(r)
            }
            def isServer = r.isServer()
            if (isServer) {
                appdefRes = toServer(r)
            }
            def isService = r.isService()
            if (isService) {
                appdefRes = toService(r)
            }

            Resource(id : r.id,
                     name : r.name,
                     description : appdefRes.description,
                     location : appdefRes.location,
                     instanceId : r.entityId.id,
                     typeId : r.entityId.type) {
                if (verbose) {
                    try {
                        def config = r.getConfig()
                        config.each { k, v ->
                            if (v.type.equals("configResponse")) {
                                ResourceConfig(key: k, value: v.value)
                            }
                        }
                        config.each { k, v ->
                            if (v.type.equals("cprop")) {
                                ResourceProperty(key: k, value: v.value)
                            }
                        }
                    } catch (Throwable t) {
                        // Invalid confi?. Bad DB entry?
                        log.error("Exception thrown while retrieving config for Resource ID " + r.id + " probably needs to be deleted manually")
                    }
                }
                if (children && !isService) {
                    r.getViewableChildren(user).each { child ->
                        out << getResourceXML(user, child, verbose, children)
                    }
                }
                try { 
                    ResourcePrototype(instanceId: r.prototype.instanceId,
                                      resourceTypeId: r.prototype.resourceType.id - 600,
                                      id : r.prototype.id,
                                      name : r.prototype.name)

                    if (isPlatform) {
                        def p = appdefRes
                        def a = p.agent
                        Agent(id             : a.id,
                            address        : a.address,
                            port           : a.port,
                            version        : a.version,
                            unidirectional : a.unidirectional)
                        for (ip in p.ips) {
                            Ip(address : ip.address,
                               netmask : ip.netmask,
                               mac     : ip.macAddress)
                        }

                        ResourceInfo(key: PROP_FQDN, value: p.fqdn)
                    } else if (isServer) {
                        def s = appdefRes
                        ResourceInfo(key: PROP_INSTALLPATH, value: s.installPath)
                        ResourceInfo(key: PROP_AIIDENIFIER, value: s.autoinventoryIdentifier)
                    } else if (isService) {
                        def s = appdefRes
                        ResourceInfo(key: PROP_AIIDENIFIER, value: s.autoinventoryIdentifier)
                    }
                } catch (Throwable t) {
                    // Invalid confi?. Bad DB entry?
                    log.error("Exception thrown while retrieving info for Resource ID " + r.id + " probably needs to be deleted manually")
                }

            }
        }
    }


    private Closure getAlertDefinitionXML(d, excludeIds) {
        return getAlertDefinitionXML(d, excludeIds, false)
    }

    private Closure getAlertDefinitionXML(d, excludeIds, showAllActions) {
        { out ->
            def attrs = [name: d.name,
                         description: d.description,
                         priority: d.priority,
                         active: d.active,
                         enabled: d.enabled,
                         frequency: d.frequencyType,
                         count: d.count,
                         range: d.range,
                         willRecover: d.willRecover,
                         notifyFiltered: d.notifyFiltered,
                         controlFiltered: d.controlFiltered,
                         ctime: d.ctime,
                         mtime: d.mtime]

            if (!excludeIds) {
                attrs['id'] = d.id
            }

            // parent is nullable.
            if (d.parent != null) {
                attrs['parent'] = d.parent.id
            }

            AlertDefinition(attrs) {

                if (d.resource) {
                    if (d.parent != null && d.parent.id == 0) {
                        ResourcePrototype(id: d.resource.id,
                                          name: d.resource.name)
                    } else {
                        Resource(id : d.resource.id,
                                 name : d.resource.name)
                    }
                }
                if (d.escalation) {
                    def e = d.escalation
                    Escalation(id :           e.id,
                               name :         e.name,
                               description :  e.description,
                               pauseAllowed : e.pauseAllowed,
                               maxPauseTime : e.maxPauseTime,
                               notifyAll :    e.notifyAll,
                               repeat :       e.repeat)
                }
                for (c in d.conditions) {
                    // Attributes common to all conditions
                    def conditionAttrs = [required: c.required,
                                          type: c.type]

                    if (c.type == EventConstants.TYPE_THRESHOLD) {
                        def metric = getTemplate(c.measurementId, d.typeBased)
                        if (!metric) {
                            log.warn("HQAPI WARN: Unable to find metric " + c.measurementId +
                                     "for definition " + d.name)
                            continue
                        } else {
                            conditionAttrs["thresholdMetric"] = metric.name
                            conditionAttrs["thresholdComparator"] = c.comparator
                            conditionAttrs["thresholdValue"] = c.threshold
                        }
                    } else if (c.type == EventConstants.TYPE_BASELINE) {
                        def metric = getTemplate(c.measurementId, d.typeBased)
                        if (!metric) {
                            log.warn("HQAPI WARN: Unable to find metric " + c.measurementId +
                                     "for definition " + d.name)
                            continue
                        } else {
                            conditionAttrs["baselineMetric"] = metric.name
                            conditionAttrs["baselineComparator"] = c.comparator
                            conditionAttrs["baselinePercentage"] = c.threshold
                            conditionAttrs["baselineType"] = c.optionStatus
                        }
                    } else if (c.type == EventConstants.TYPE_CHANGE) {
                        def metric = getTemplate(c.measurementId, d.typeBased)
                        if (!metric) {
                            log.warn("HQAPI WARN: Unable to find metric " + c.measurementId +
                                     "for definition " + d.name)
                            continue
                        } else {
                            conditionAttrs["metricChange"] = metric.name
                        }
                    } else if (c.type == EventConstants.TYPE_CUST_PROP) {
                        conditionAttrs["property"] = c.name
                    } else if (c.type == EventConstants.TYPE_LOG) {
                        int level = c.name.toInteger()
                        conditionAttrs["logLevel"] = ResourceLogEvent.getLevelString(level)
                        conditionAttrs["logMatches"] = c.optionStatus
                    } else if (c.type == EventConstants.TYPE_ALERT) {
                        def alert = aMan.getByIdNoCheck(c.measurementId)
                        if (alert == null) {
                            // TODO: This is not handled correctly in HQ.  NPE
                            //       is thrown rather than null returned.
                            log.warn("HQAPI WARN: Unable to find recover condition " +
                                     c.measurementId + " for " + c.name)
                            continue
                        } else {
                            if (!excludeIds) {
                               conditionAttrs["recoverId"] = alert.id
                            }
                            conditionAttrs["recover"] = alert.name
                        }
                    } else if (c.type == EventConstants.TYPE_CFG_CHG) {
                        conditionAttrs["configMatch"] = c.optionStatus
                    } else if (c.type == EventConstants.TYPE_CONTROL) {
                        conditionAttrs["controlAction"] = c.name
                        conditionAttrs["controlStatus"] = c.optionStatus
                    } else {
                        log.warn("HQAPI WARN: Unhandled condition type " + c.type +
                                 " for condition " + c.name)
                    }
                    // Write it out
                    AlertCondition(conditionAttrs)
                }

                for (a in d.actions) {
                    if (a.className == "com.hyperic.hq.bizapp.server.action.control.ScriptAction" ||
                        a.className == "org.hyperic.hq.bizapp.server.action.integrate.OpenNMSAction" ||
                        a.className == "com.hyperic.hq.bizapp.server.action.alert.SnmpAction") {
                        AlertAction(id: a.id,
                                    className: a.className) {
                            def config = ConfigResponse.decode(a.config)
                            for (key in config.keys) {
                                AlertActionConfig(key: key,
                                                  value: config.getValue(key))
                            }
                        }
                    } else if (a.className == "com.hyperic.hq.bizapp.server.action.control.ControlAction") {
                        def config = ConfigResponse.decode(a.config)
                        def appdefType = config.getValue("appdefType")?.toInteger()
                        def appdefId = config.getValue("appdefId")?.toInteger()
                        def resource

                        if (appdefType == 1) {
                            resource = resourceHelper.find('platform':appdefId)
                        } else if (appdefType == 2) {
                            resource = resourceHelper.find('server':appdefId)
                        } else if (appdefType == 3) {
                            resource = resourceHelper.find('service':appdefId)
                        } else {
                            log.warn("HQAPI WARN: Unable to find resource appdefType=" +
                                     appdefType + " appdefId=" + appdefId)
                            continue // Skip this action
                        }

                        if (resource) {
                            AlertAction(id: a.id,
                                        className: a.className) {
                                AlertActionConfig(key: 'resourceId',
                                                  value: resource.id)
                                AlertActionConfig(key: 'action',
                                                  value: config.getValue('action'))
                                AlertActionConfig(key: 'params',
                                    value: config.getValue('params'))
                            }
                        }
                    } else if (a.className == "com.hyperic.hq.bizapp.server.action.email.EmailAction") {
                         def config = ConfigResponse.decode(a.config)
                         def ids = config.getValue("names")
                         def listType = config.getValue("listType")?.toInteger()

                         def names = getNotificationNames(listType,ids)
                         if (names != null && names.length() > 0) {
                            AlertAction(id: a.id,
                                         className: a.className) {
                                AlertActionConfig(key: 'notifyType',
                                                  value: EMAIL_NOTIFY_TYPE[listType])
                                AlertActionConfig(key: 'names',
                                                  value: names)
                            }
                         }
                    } else if (showAllActions) {
                        AlertAction(id: a.id,
                                    className: a.className)
                    }
                }
            }
        }
    }


    private Closure getResourceXMLWithAlertDefinitions(user, r, boolean verbose, boolean children) {
        { doc ->
            def appdefRes = null
            def isPlatform = r.isPlatform()
            if (isPlatform) {
                appdefRes = toPlatform(r)
            }
            def isServer = r.isServer()
            if (isServer) {
                appdefRes = toServer(r)
            }
            def isService = r.isService()
            if (isService) {
                appdefRes = toService(r)
            }

            Resource(id : r.id,
                     name : r.name,
                     description : appdefRes.description,
                     location : appdefRes.location,
                     instanceId : r.entityId.id,
                     typeId : r.entityId.type) {
                if (verbose) {
                    try {
                        def config = r.getConfig()
                        config.each { k, v ->
                            if (v.type.equals("configResponse")) {
                                ResourceConfig(key: k, value: v.value)
                            }
                        }
                        config.each { k, v ->
                            if (v.type.equals("cprop")) {
                                ResourceProperty(key: k, value: v.value)
                            }
                        }
                    } catch (Throwable t) {
                        // Invalid confi?. Bad DB entry?
                        log.error("Exception thrown while retrieving config for Resource ID " + r.id + " probably needs to be deleted manually")
                    }
                }
                if (children && !isService) {
                    r.getViewableChildren(user).each { child ->
                        out << getResourceXMLWithAlertDefinitions(user, child, verbose, children)
                    }
                }
                //try { 
                    ResourcePrototype(instanceId: r.prototype.instanceId,
                                      resourceTypeId: r.prototype.resourceType.id - 600,
                                      id : r.prototype.id,
                                      name : r.prototype.name)

                    if (isPlatform) {
                        def p = appdefRes
                        def a = p.agent
                        Agent(id             : a.id,
                            address        : a.address,
                            port           : a.port,
                            version        : a.version,
                            unidirectional : a.unidirectional)
                        for (ip in p.ips) {
                            Ip(address : ip.address,
                               netmask : ip.netmask,
                               mac     : ip.macAddress)
                        }

                        ResourceInfo(key: PROP_FQDN, value: p.fqdn)
                    } else if (isServer) {
                        def s = appdefRes
                        ResourceInfo(key: PROP_INSTALLPATH, value: s.installPath)
                        ResourceInfo(key: PROP_AIIDENIFIER, value: s.autoinventoryIdentifier)
                    } else if (isService) {
                        def s = appdefRes
                        ResourceInfo(key: PROP_AIIDENIFIER, value: s.autoinventoryIdentifier)
                    }

                    //definitions = aMan.findAlertDefinitions(user, r.entityId)
                    def definitions = aMan.findAlertDefinitions(user, r)
                    for (definition in definitions.sort {a, b -> a.id <=> b.id}) {
                        def alertDefinitionXML = getAlertDefinitionXML(definition, false)
                        out << alertDefinitionXML
                        //log.info(alertDefinitionXML)
                    }
                //} 
                /*catch (Throwable t) {
                    throw e
                    // Invalid confi?. Bad DB entry?
                    log.error("Exception thrown while retrieving info for Resource ID " + r.id + " probably needs to be deleted manually")
                }*/

            }
        }
    }




    private Closure getPrototypeXML(p) {
        { doc -> 
            ResourcePrototype(instanceId: p.instanceId,
                              resourceTypeId: p.resourceType.id - 600,
                              id   : p.id,
                              name : p.name)
        }
    }

    private Closure getResourceEdgeXML(edges) {
    	{ doc ->
    		for (e in edges.sort {a, b -> a.to.name <=> b.to.name}) {
    			ResourceEdge(relation : e.relation.name,
    					 	 distance : e.distance) {
    				ResourceFrom() {
    					Resource(id : e.from.id,
    						 	 name : e.from.name)
    				}
    				ResourceTo() {
                        Resource(id : e.to.id,
                        		 name : e.to.name)
                    }    			
    			}
    		}                    
    	}
    }

    private Closure getResourceEdgeGroupingXML(resourceRelation, parent, childrenEdges) {
    	{ doc ->
    		ResourceEdge(relation : resourceRelation,
    					 distance : 1) {
    			ResourceFrom() {
    				Resource(id : parent.id,
    						 name : parent.name)
    			}
    			ResourceTo() {
                    for (e in childrenEdges.sort {a, b -> a.to.name <=> b.to.name}) {
                        if (e.distance == 1) {
                        	Resource(id : e.to.id,
                        		 	 name : e.to.name)
                        }
                    }    			
    			}
    		}                     
    	}
    }

    private String getCause(Throwable t) {
        while (t.getCause()) {
            t = t.getCause()
        }
        return t.getMessage()
    }


    /**
     * Loop waiting for a resource to have it's metrics enabled.
     */
    private boolean metricsEnabled(res) {
        for (int i = 0; i < 10; i++) {
            def metrics = res.enabledMetrics
            if (metrics.size() == 0) {
                log.info("Metrics not yet enabled for new resource " + res.name +
                         ", waiting...")
                try {
                    Thread.sleep(2000)
                } catch (InterruptedException e) {
                    // Ignore
                }
            } else {
                log.info("Found " + metrics.size() + " metrics for " + res.name)
                return true
            }
        }
        return false
    }



    def getResourcePrototypes(params) {
        def existing = params.getOne('existing')?.toBoolean()

        def prototypes
        if (existing) {
            prototypes = resourceHelper.findAppdefPrototypes()
        } else {
            prototypes = resourceHelper.findAllAppdefPrototypes()
        }
        
        renderXml() {
            out << ResourcePrototypesResponse() {
                out << getSuccessXML()
                for (p in prototypes.sort {a, b -> a.name <=> b.name}) {
                    out << getPrototypeXML(p)
                }
            }
        }
    }

    def getResourcePrototype(params) {
        def name = params.getOne("name")

        def prototype
        if (name) {
            prototype = resourceHelper.find(prototype: name)
        }

        renderXml() {
            out << ResourcePrototypeResponse() {
                if (!name) {
                    out << getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                         "Resource prototype not given")
                } else if (!prototype) {
                    out << getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                         "Unable to find type " + name)
                } else {
                    out << getSuccessXML()
                    out << getPrototypeXML(prototype)
                }
            }
        }
    }

    def createPlatform(params) {
        def createRequest = new XmlParser().parseText(getPostData())
        def xmlResource = createRequest['Resource']
        def xmlPrototype = createRequest['Prototype']
        def xmlIps = createRequest['Ip']
        def xmlAgent = createRequest['Agent']
        def fqdn = createRequest['Fqdn']?.text();

        if (!xmlResource || xmlResource.size() != 1 ||
            !xmlPrototype || xmlPrototype.size() != 1 ||
            !xmlIps || xmlIps.size() < 1 ||
            !xmlAgent || xmlAgent.size() != 1 ||
            !fqdn)
        {
            renderXml() {
                ResourceResponse() {
                    out << getFailureXML(ErrorCode.INVALID_PARAMETERS)
                }
            }
            return
        }

        def parent = resourceHelper.findRootResource()
        def agent = getAgent(xmlAgent[0].'@id'?.toInteger(),
                             xmlAgent[0].'@address',
                             xmlAgent[0].'@port'?.toInteger())
        def prototype = resourceHelper.find(prototype: xmlPrototype[0].'@name')

        if (!parent) {
            renderXml() {
                ResourceResponse() {
                    out << getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                         "Parent resource not found")
                }
            }
            return
        }

        if (!agent) {
            renderXml() {
                ResourceResponse() {
                    out << getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                         "Agent with id=" + xmlAgent[0].'@id' +
                                         " address=" + xmlAgent[0].'@address' +
                                         " port=" + xmlAgent[0].'@port' +
                                         " not found")
                }
            }
        }

        if (!prototype) {
            renderXml() {
                ResourceResponse() {
                    out << getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                         "Resource type " +
                                         xmlPrototype[0].'@name' +
                                         " not found")
                }
            }
            return
        }

        def resourceXml = xmlResource[0]
        def cfgXml = resourceXml['ResourceConfig']
        def cfg = [:]
        cfgXml.each { c ->
            cfg.put(c.'@key', c.'@value')
        }
        cfg.put('fqdn', fqdn)

        def ips = []
        xmlIps.each { ip ->
            ips << [address: ip.'@address', netmask: ip.'@netmask', mac: ip.'@mac']
        }

        def resource
        try {
            resource = prototype.createInstance(parent, resourceXml.'@name',
                                                user, cfg, agent, ips)
        } catch (Throwable t) {
            String cause = getCause(t)
            renderXml() {
                ResourceResponse() {
                    out << getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                         "Error creating '" +
                                         resourceXml.'@name' + "': " + cause)
                }
            }
            log.warn("HQAPI WARN: Error creating resource", t)
            return
        }

        renderXml() {
            ResourceResponse() {
                out << getSuccessXML()
                // Only return this resource w/ it's config
                out << getResourceXML(user, resource, true, false)
            }
        }
    }


    def createAlertDefinition(xmlDef, rid) {
        def out = ""
        def definitions = []
        def sess = org.hyperic.hq.hibernate.SessionManager.currentSession()
        //for (xmlDef in syncRequest['AlertDefinition']) {
        def failureXml = null
        def resource = null 
        boolean typeBased
        def existing = null
        Integer id = xmlDef.'@id'?.toInteger()
        resource = getResource(rid)
        if (!resource) { 
            failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                    "Resource id=" + rid +
                            " not found")
            log.warn("HQAPI ERROR: " + "Resource id=" + rid + " not found")
            return
        }

        // Required attributes, basically everything but description
        ['controlFiltered', 'notifyFiltered', 'willRecover', 'range', 'count',
         'frequency', 'active', 'priority',
         'name'].each { attr ->
            if (xmlDef."@${attr}" == null) {
                failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                          "Required attribute " + attr +
                                          " not found for definition " +
                                          xmlDef.'@name')
              log.warn("HQAPI ERROR: " + 
                      "Required attribute " + attr +
                      " not found for definition " +
                      xmlDef.'@name')
            }
        }

        // At least one condition is always required
        if (!xmlDef['AlertCondition'] || xmlDef['AlertCondition'].size() < 1) {
            failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                       "At least 1 AlertCondition is " +
                                       "required for definition " +
                                       xmlDef.'@name')
            log.warn("HQAPI ERROR: "  
                    + "At least 1 AlertCondition is " 
                    + "required for definition " 
                    + xmlDef.'@name')
        }

        // Configure any escalations
        def escalation = null
        if (xmlDef['Escalation'].size() == 1) {

            def xmlEscalation = xmlDef['Escalation'][0]
            def escName = xmlEscalation.'@name'
            if (escName) {
                escalation = escalationHelper.getEscalation(null, escName)
            }

            if (!escalation) {
                failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                           "Unable to find escalation with " +
                                           "name '" + escName + "'")
               log.warn( "HQAPI ERROR: " + 
               "Unable to find escalation with " +
               "name '" + escName + "'")
            }
        }

        // Alert priority must be 1-3
        int priority = xmlDef.'@priority'.toInteger()
        if (priority < 1 || priority > 3) {
            failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                       "AlertDefinition priority must be " +
                                       "between 1 (low) and 3 (high) " +
                                       "found=" + priority)
               log.warn( "HQAPI ERROR: " + 
                       "AlertDefinition priority must be " +
                       "between 1 (low) and 3 (high) " +
                       "found=" + priority)
        }

        // Alert frequency must be 0-4
        int frequency = xmlDef.'@frequency'.toInteger()
        if (frequency < 0 || frequency > 4) {
            failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                       "AlertDefinition frequency must be " +
                                       "between 0 and 4 " +
                                       "found=" + frequency)
               log.warn( "HQAPI ERROR: " + 
                       "AlertDefinition frequency must be " +
                       "between 0 and 4 " +
                       "found=" + frequency)
        }

        // Error with AlertDefinition attributes
        if (failureXml) {
            renderXml() {
                AlertDefinitionsResponse() {
                    out << failureXml
                }
            }
            return
        }

        def aeid;
        if (typeBased) {
            aeid = new AppdefEntityTypeID(resource.appdefType,
                                          resource.instanceId)
        } else {
            aeid = resource.entityId
        }

        AlertDefinitionValue adv = new AlertDefinitionValue();
        adv.id          = existing?.id
        adv.name        = xmlDef.'@name'
        adv.description = xmlDef.'@description'
        adv.appdefType  = aeid.type
        adv.appdefId    = aeid.id
        adv.priority    = xmlDef.'@priority'?.toInteger()
        adv.active      = xmlDef.'@active'.toBoolean()
        adv.willRecover = xmlDef.'@willRecover'.toBoolean()
        adv.notifyFiltered = xmlDef.'@notifyFiltered'?.toBoolean()
        adv.controlFiltered = xmlDef.'@controlFiltered'?.toBoolean()
        adv.frequencyType  = xmlDef.'@frequency'.toInteger()
        adv.count = xmlDef.'@count'.toLong()
        adv.range = xmlDef.'@range'.toLong()
        adv.escalationId = escalation?.id
        if (existing) {
            // If the alert is pre-existing, set the parent id.
            adv.parentId = existing.parent?.id
        }

        def templs
        if (typeBased) {
            def args = [:]
            args.all = 'templates'
            args.resourceType = resource.name
            templs = metricHelper.find(args)
        } else {
            // TODO: This gets all metrics, should warn if that metric is disabled?
            templs = resource.metrics
        }

        def isRecovery = false

        for (xmlAction in xmlDef['AlertAction']) {
            def actionId  = xmlAction.'@id'?.toInteger()
            def className = xmlAction.'@className'

            if (!className) {
                // Nothing to do
                continue
            }

            def cfg = [:]
            // Special translation for ControlActions for Resource ids
            if (className == "com.hyperic.hq.bizapp.server.action.control.ControlAction") {
                def rId = xmlAction['AlertActionConfig'].find {
                    it.'@key' == 'resourceId'
                }?.'@value'?.toInteger()

                def action = xmlAction['AlertActionConfig'].find {
                    it.'@key' == 'action'
                }?.'@value'

                def par = xmlAction['AlertActionConfig'].find {
                    it.'@key' == 'params'
                }?.'@value'

        
                def cResource = null
                try {
                    cResource = getResource(rId)
                } catch (PermissionException e) {
                    // Ignore
                }
                if (cResource != null && action != null) {
                    def actions = cResource.getControlActions(user)
                    if (!actions.find { it == action }) {
                        log.warn("HQAPI WARN: Resource " + cResource.name + " does not " +
                                 "support action " + action)
                        continue
                    }

                    cfg['appdefType'] = Integer.toString(cResource.entityId.type)
                    cfg['appdefId'] = Integer.toString(cResource.entityId.id)
                    cfg['action'] = action
                    cfg['params'] = par
                } else {
                    // If the resource is not found, don't add the action
                    log.warn("HQAPI WARN: Ignoring invalid ControlAction config " +
                             xmlAction['AlertActionConfig'])
                    continue
                }
            } else if (className == "com.hyperic.hq.bizapp.server.action.email.EmailAction") {
                def typeName = xmlAction['AlertActionConfig'].find {
                    it.'@key' == 'notifyType'
                }?.'@value'

                def names = xmlAction['AlertActionConfig'].find {
                    it.'@key' == 'names'
                }?.'@value'

                def type = EMAIL_NOTIFY_TYPE.find { it.value == typeName }?.key

                if (!type) {
                    log.warn("HQAPI WARN: Ignoring invalid EmailAction type " + typeName)
                    continue
                }

                def notificationIds = getNotificationIds(type, names)
                if (notificationIds == null || notificationIds.length() == 0) {
                    log.warn("HQAPI WARN: Ignoring invalid EmailAction notification=" + names)
                    continue
                }

                cfg['listType'] = type.toString()
                cfg['names'] = notificationIds
                cfg['sms'] = 'false' // XXX: Legacy a presume..
            } else {
                for (xmlConfig in xmlAction['AlertActionConfig']) {
                    cfg[xmlConfig.'@key'] = xmlConfig.'@value'
                }
            }

            ConfigResponse configResponse =  new ConfigResponse(cfg)
            ActionValue action = new ActionValue(actionId, className,
                                                 configResponse.encode(),
                                                 null)
            adv.addAction(action)
        }

        for (xmlCond in xmlDef['AlertCondition']) {
            AlertConditionValue acv = new AlertConditionValue()
            def acError

            acError = checkRequiredAttributes(adv.name, xmlCond,
                                              ['required','type'])
            if (acError != null) {
                failureXml = acError
                log.warn( "HQAPI ERROR: " + acError)  
                break
            }

            acv.required = xmlCond.'@required'.toBoolean()
            acv.type = xmlCond.'@type'.toInteger()

            switch (acv.type) {
                case EventConstants.TYPE_THRESHOLD:
                    acError = checkRequiredAttributes(adv.name, xmlCond,
                                                      ['thresholdMetric',
                                                       'thresholdComparator',
                                                       'thresholdValue'])
                    if (acError != null) {
                        failureXml = acError
                        log.warn( "HQAPI ERROR: " + acError)  
                        break
                    }

                    acv.name = xmlCond.'@thresholdMetric'
                    def template = templs.find {
                        acv.name == (typeBased ? it.name : it.template.name)
                    }
                    if (!template) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                                   "Unable to find metric " +
                                                   acv.name + " for " +
                                                   resource.name)
                        log.warn( "HQAPI ERROR: "  + 
                                   "Unable to find metric " +
                                   acv.name + " for " +
                                   resource.name)
                        break
                    }

                    acv.measurementId = template.id
                    acv.comparator    = xmlCond.'@thresholdComparator'
                    acv.threshold     = Double.valueOf(xmlCond.'@thresholdValue')
                    break
                case EventConstants.TYPE_BASELINE:
                    acError = checkRequiredAttributes(adv.name, xmlCond,
                                                      ['baselineMetric',
                                                       'baselineComparator',
                                                       'baselinePercentage',
                                                       'baselineType'])
                    if (acError != null) {
                        failureXml = acError
                        log.warn( "HQAPI ERROR: "  +  acError)
                        break
                    }

                    acv.name = xmlCond.'@baselineMetric'
                    def template = templs.find {
                        acv.name == (typeBased ? it.name : it.template.name)
                    }
                    if (!template) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                                   "Unable to find metric " +
                                                   acv.name + " for " +
                                                   resource.name)
                        log.warn( "HQAPI ERROR: "  + 
                                   "Unable to find metric " +
                                   acv.name + " for " +
                                   resource.name)

                        break
                    }

                    def baselineType = xmlCond.'@baselineType'
                    if (!baselineType.equals("min") &&
                        !baselineType.equals("max")&&
                        !baselineType.equals("mean")) {
                        failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                                   "Invalid baseline type '" +
                                                   baselineType + "'")
                        break
                    }


                    acv.measurementId = template.id
                    acv.comparator    = xmlCond.'@baselineComparator'
                    acv.threshold     = Double.valueOf(xmlCond.'@baselinePercentage')
                    acv.option        = baselineType
                    break
                case EventConstants.TYPE_CONTROL:
                    acError = checkRequiredAttributes(adv.name, xmlCond,
                                                      ['controlAction',
                                                       'controlStatus'])
                    if (acError != null) {
                        failureXml = acError
                        log.warn( "HQAPI ERROR: "  +  acError)
                        break
                    }

                    def controlStatus = xmlCond.'@controlStatus'
                    if (!controlStatus.equals("Completed") &&
                        !controlStatus.equals("In Progress") &&
                        !controlStatus.equals("Failed")) {
                        failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                                   "Invalid control condition " +
                                                   "status " + controlStatus)
                        log.warn( "HQAPI ERROR: "  + 
                                   "Invalid control condition " +
                                   "status " + controlStatus)
                        break
                    }

                    // TODO: Check resource for given control action
                    acv.name   = xmlCond.'@controlAction'
                    acv.option = controlStatus
                    break
                case EventConstants.TYPE_CHANGE:
                    acError = checkRequiredAttributes(adv.name, xmlCond,
                                                      ['metricChange'])
                    if (acError != null) {
                        failureXml = acError
                        log.warn( "HQAPI ERROR: "  + acError)
                        break
                    }

                    acv.name = xmlCond.'@metricChange'
                    def template = templs.find {
                        acv.name == (typeBased ? it.name : it.template.name)
                    }
                    if (!template) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                                   "Unable to find metric " +
                                                   acv.name + " for " +
                                                   resource.name)
                        log.warn( "HQAPI ERROR: "  + 
                                   "Unable to find metric " +
                                   acv.name + " for " +
                                   resource.name)
                        break
                    }
                    acv.measurementId = template.id
                    break
                case EventConstants.TYPE_ALERT:
                    acError = checkRequiredAttributes(adv.name, xmlCond,
                                                      ['recover'])
                    if (acError != null) {
                        failureXml = acError
                        log.warn( "HQAPI ERROR: "  +  acError)
                        break
                    }

                    isRecovery = true

                    // If a resource alert, look up alert by name
                    // TODO: This needs to be looked up by alert definition id
                    // to avoid collisions where the alert definition names
                    // are the same
                    if (resource) {
                        log.debug("Looking up alerts for resource=" + resource.id)
                        def resourceDefs = resource.getAlertDefinitions(user)
                        def recovery = resourceDefs.find { it.name == xmlCond.'@recover' }
                        if (recovery) {
                            log.info("Found recovery definition " + recovery.id)
                            acv.measurementId = recovery.id
                            break
                        }
                    }

                    if (!acv.measurementId) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                                   "Unable to find recovery " +
                                                   "with name '" +
                                                   xmlCond.'@recover' + "'")
                        log.warn( "HQAPI ERROR: "  + 
                                   "Unable to find recovery " +
                                   "with name '" +
                                   xmlCond.'@recover' + "'")
                    }

                    break
                case EventConstants.TYPE_CUST_PROP:
                    acError = checkRequiredAttributes(adv.name, xmlCond,
                                                      ['property'])
                    if (acError != null) {
                        failureXml = acError
                        log.warn( "HQAPI ERROR: "  + acError)
                        break
                    }
                    acv.name = xmlCond.'@property'
                    break
                case EventConstants.TYPE_LOG:
                    acError = checkRequiredAttributes(adv.name, xmlCond,
                                                      ['logLevel',
                                                       'logMatches'])
                    if (acError != null) {
                        failureXml = acError
                        log.warn( "HQAPI ERROR: "  +  acError)
                        break
                    }


                    def level = EVENT_LEVEL_TO_NUM[xmlCond.'@logLevel']
                    if (level == null) {
                        failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                                   "Unknown log level " +
                                                   xmlCond.'@logLevel')
                        log.warn( "HQAPI ERROR: "  + 
                                   "Unknown log level " +
                                   xmlCond.'@logLevel')
                        break
                    }

                    acv.name = level.toString()
                    acv.option = xmlCond.'@logMatches'
                    break
                case EventConstants.TYPE_CFG_CHG:

                    def configMatch = xmlCond.'@configMatch'
                    if (configMatch) {
                        acv.option = configMatch
                    }
                    break
                default:
                    failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                               "Unhandled AlertCondition " +
                                               "type " + acv.type + " for " +
                                               adv.name)
                    log.warn( "HQAPI ERROR: "  + 
                           "Unhandled AlertCondition " +
                           "type " + acv.type + " for " +
                           adv.name)
            }

            // Error with AlertCondition
            if (failureXml) {
                renderXml() {
                    AlertDefinitionsResponse() {
                        out << failureXml
                    }
                }
                return
            }
            adv.addCondition(acv)
        }

        // TODO: Migrate this to AlertHelper
        try {
            def sessionId = SessionManager.instance.put(user)
            if (adv.id == null) {
                def newDef
                if (typeBased) {
                    newDef =
                        eventBoss.createResourceTypeAlertDefinition(sessionId,
                                                                    aeid, adv)
                } else {
                    newDef = eventBoss.createAlertDefinition(sessionId, adv)
                }
                adv.id = newDef.id
            } else {
                if (typeBased
                        && (!adv.name.equals(existing.name)
                            || !adv.description.equals(existing.description)
                            || adv.priority != existing.priority
                            || adv.active != existing.active)) {
                    
                    eventBoss.updateAlertDefinitionBasic(sessionId, adv.id,
                                                         adv.name, adv.description,
                                                         adv.priority, adv.active)
                }
                eventBoss.updateAlertDefinition(sessionId, adv)
            }
        } catch (PermissionException e) {
            failureXml = getFailureXML(ErrorCode.PERMISSION_DENIED)
            log.warn( "HQAPI ERROR: "  +  failureXml)
        } catch (Exception e) {
            log.error("Error updating alert definition", e)
            failureXml = getFailureXML(ErrorCode.UNEXPECTED_ERROR,
                                       e.getMessage())
            log.warn( "HQAPI ERROR: "  +  failureXml)
        }

        // Error with save/update
        if (failureXml) {
            renderXml() {
                AlertDefinitionsResponse() {
                    out << failureXml
                }
            }
            return
        }

        def pojo = aMan.getByIdNoCheck(adv.id)

        // Deal with Escalations
        if (escalation) {
            // TODO: Backend should handle escalations on recovery alerts
            if (isRecovery) {
                log.warn("HQAPI WARN: Skipping escalation for definition '" + pojo.name +
                         "'.  Escalations not allowed for recovery alerts.")
            } else {
                pojo.setEscalation(user, escalation)
            }
        } else {
            pojo.unsetEscalation(user)
        }

        // Keep synced definitions for sync return XML
        definitions << pojo.id
        sess.flush()
        sess.clear()
        //}
    }



    def createResource(parentId, xmlResource, prototypeName) {
        def failureXml = ""
        if (!xmlResource) {
            failureXml <<  getFailureXML(ErrorCode.INVALID_PARAMETERS, "xmlResource cannot be null")
            log.warn("HQAPI ERROR: Error creating resource: " + failureXml)
            return null
        }

        def parent = getResource(parentId.toInteger())
        def prototype = resourceHelper.find(prototype: prototypeName)
        if (!parent) {
            failureXml << getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                 "Parent resource " + parentId + " not found")
            log.warn("HQAPI ERROR: Error creating resource: " + failureXml)
            return null
        }
        if (!prototype) {
            failureXml << getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                 "Resource type " + prototypeName + " not found")
            log.warn("HQAPI ERROR: Error creating resource: " + failureXml)
            return null
        }

        def resourceXml = xmlResource
        def cfgXml = resourceXml['ResourceConfig']
        def cfg = [:]
        cfgXml.each { c ->
            cfg.put(c.'@key', c.'@value')
        }

        def resource
        try {
            resource = prototype.createInstance(parent, resourceXml.'@name', user, cfg)
            // Must loop waiting for metrics to be created in the background.
        } catch (Throwable t) {
            String cause = getCause(t)
            failureXml << getFailureXML(ErrorCode.INVALID_PARAMETERS,
                             "Error creating '" + resourceXml.'@name' + "': " + cause)
            log.warn("HQAPI ERROR: Error creating resource: " + failureXml)
            return null
        }
        return resource
    }


    def create(params) {
        def createRequest = new XmlParser().parseText(getPostData())
        for (type1 in createRequest.Resource) { 
            try {
                for(alert in type1.AlertDefinition) { 
                    //create alertdefinition
                    def result = createAlertDefinition(alert, type1.'@copyToId'?.toInteger())
                    if (result == null){ 
                        log.warn("HQAPI INFO: Failed creating alertDefinition " 
                        + alert.'@name' + " for resource with id " 
                        + type1.'@copyToId')
                    } else { 
                        log.warn("HQAPI INFO: Successfully created alertDefinition " 
                        + alert.'@name' + " for resource with id " 
                        + type1.'@copyToId')
                    }
                }
            } catch(Throwable t) {
                //log and break
                log.warn("HQAPI ERROR: failed creating  AlertDefinition " + alert.'@name' + " for resource with id " + type1.'@copyToId')
                String cause = getCause(t)
                log.warn("HQAPI ERROR: Error creating AlertDefinition: " + cause)
                continue
            }


            for(type2 in type1.Resource){ 
                try {
                    //create server 
                    def server = createResource(type1.'@copyToId'?.toInteger(), type2, type2.ResourcePrototype.'@name')
                    if (server == null) {
                        log.warn("HQAPI INFO: Failed creating server.. " + type2.'@name' 
                                + " with prototype: " + type2.ResourcePrototype.'@name' 
                                + " with resource id: " + server.id);
                    } else { 
                        log.warn("HQAPI INFO: successfully created server.. " + type2.'@name' 
                                + " with prototype: " + type2.ResourcePrototype.'@name' 
                                + " with resource id: " + server.id);
                    }
                    for (type3 in type2.Resource){ 
                        try {
                            //create service
                            def  service
                            service = createResource(server.id, type3, type3.ResourcePrototype.'@name')
                            if (service == null) { 
                                log.warn("HQAPI INFO: Failed creating service.. " 
                                + type3.'@name' + " with prototype: " 
                                + type3.ResourcePrototype.'@name');
                            } else { 
                                log.warn("HQAPI INFO: Successfully created service.. " 
                                + type3.'@name' + " with prototype: " 
                                + type3.ResourcePrototype.'@name');
                            }
                            for(alert in type3.AlertDefinition) { 
                                try {
                                    //create service AlertDefinition
                                    def result
                                    if (metricsEnabled(service)) { 
                                        result = createAlertDefinition(alert, service.id)
                                    }
                                    if (result == null) { 
                                        log.warn("HQAPI INFO: Failed creating AlertDefinition.. " 
                                                    + " with name "  + alert.'@name' + " to resource "
                                                    + type3.'@name' + " with prototype: " 
                                                    + type3.ResourcePrototype.'@name');
                                    } else { 
                                        log.warn("HQAPI INFO: successfully created AlertDefinition.. " 
                                                    + " with name "  + alert.'@name' + " to resource "
                                                    + type3.'@name' + " with prototype: " 
                                                    + type3.ResourcePrototype.'@name');
                                    }
                                } catch(Throwable t) {
                                    //log and break
                                    log.warn("HQAPI INFO: Failed craeating AlertDefinition.. " 
                                                + " with name "  + alert.'@name' + " to resource "
                                                + type3.'@name' + " with prototype: " 
                                                + type3.ResourcePrototype.'@name');
                                    String cause = getCause(t)
                                    log.warn("HQAPI ERROR: Error creating AlertDefinition: " + cause)
                                    continue
                                }
                            }
                        } catch(Throwable t) {
                            //log and break
                            log.warn("HQAPI ERROR: Failed creating service.. " + type3.'@name' + " with prototype: " + type3.ResourcePrototype.'@name');
                            String cause = getCause(t)
                            log.warn("HQAPI ERROR: Error creating service: " + cause)
                            throw new RuntimeException("HQAPI ERROR: Error creating service: " + cause)
                            break
                        }
                    }
                } catch(Throwable t) {
                    //log  and break
                    log.warn("HQAPI ERROR: Failed creating server.. " + type2.'@name' + " with prototype: " + type2.ResourcePrototype.'@name');
                    String cause = getCause(t)
                    log.warn("HQAPI ERROR: Error creating server: " + cause)
                    break
                }
            }
        }

        renderXml() {
            StatusResponse() {
                out << "<done>Check the log files for error messages if any</done>"
            }
        }

    }



    def get(params) {
        def id = params.getOne("id")?.toInteger()
        def platformName = params.getOne("platformName")
        def fqdn = params.getOne("fqdn")
        def parentOf = params.getOne("parentOf")?.toInteger()
        def platformId = params.getOne("platformId")?.toInteger()
        def aeid = params.getOne("aeid")?.toString()
        boolean children = params.getOne("children", "false").toBoolean()
        boolean verbose = params.getOne("verbose", "false").toBoolean()

        def resource = null
        def failureXml
        if (!id && !platformName && !fqdn && !platformId && !parentOf && !aeid) {
            failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS)
        } else {
            try {
                if (id) {
                    resource = getResource(id)
                    if (!resource) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                "Resource id=" + id +
                                        " not found")
                    }
                } else if (aeid) {
                    def appdefeid = new AppdefEntityID(aeid)
                    resource = resMan.findResource(appdefeid)
                    
                    if (!resource) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                "Resource aeid=" + aeid +
                                        " not found")
                    }
                } else if (platformId) {
                    def wantedResource = getResource(platformId)
                    if (!wantedResource) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                "Resource id=" + platformId +
                                        " not found")
                    } else {
                        resource = wantedResource.platform
                    }
                } else if (platformName) {
                    resource = resourceHelper.find('platform': platformName)
                    if (!resource) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                "Platform '" + platformName +
                                        "' not found")
                    }
                } else if (fqdn) {
                	resource = resourceHelper.find('byFqdn':fqdn)
                    if (!resource) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                               "Platform fqdn='" + fqdn +
                                               "' not found")
                    }
                } else if (parentOf) {
                    def child = getResource(parentOf)
                    if (!child) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                               "Resource id ='" + parentOf +
                                               "' not found")
                    } else {
                        if (child.isPlatform()) {
                            failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                                       "No parent for platform ='" + parentOf + "'")
                        } else if (child.isServer()) {
                            resource = child.toServer().platform.resource
                        } else if (child.isService()) {
                            resource = child.toService().server.resource
                        }
                    }                }
            } catch (PermissionException e) {
                failureXml = getFailureXML(ErrorCode.PERMISSION_DENIED)
            }
        }

        renderXml() {
            out << ResourceResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                    out << getResourceXML(user, resource, verbose, children)
                }
            }
        }
        
    }


    def getResourcesWithAlertDefinitions(params) {
        def id = params.getOne("id")?.toInteger()
        def platformName = params.getOne("platformName")
        def fqdn = params.getOne("fqdn")
        def parentOf = params.getOne("parentOf")?.toInteger()
        def platformId = params.getOne("platformId")?.toInteger()
        def aeid = params.getOne("aeid")?.toString()
        boolean children = params.getOne("children", "false").toBoolean()
        boolean verbose = params.getOne("verbose", "false").toBoolean()

        def resource = null
        def failureXml
        if (!id && !platformName && !fqdn && !platformId && !parentOf && !aeid) {
            failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS)
        } else {
            try {
                if (id) {
                    resource = getResource(id)
                    if (!resource) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                "Resource id=" + id +
                                        " not found")
                    }
                } else if (aeid) {
                    def appdefeid = new AppdefEntityID(aeid)
                    resource = resMan.findResource(appdefeid)
                    
                    if (!resource) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                "Resource aeid=" + aeid +
                                        " not found")
                    }
                } else if (platformId) {
                    def wantedResource = getResource(platformId)
                    if (!wantedResource) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                "Resource id=" + platformId +
                                        " not found")
                    } else {
                        resource = wantedResource.platform
                    }
                } else if (platformName) {
                    resource = resourceHelper.find('platform': platformName)
                    if (!resource) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                "Platform '" + platformName +
                                        "' not found")
                    }
                } else if (fqdn) {
                	resource = resourceHelper.find('byFqdn':fqdn)
                    if (!resource) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                               "Platform fqdn='" + fqdn +
                                               "' not found")
                    }
                } else if (parentOf) {
                    def child = getResource(parentOf)
                    if (!child) {
                        failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                               "Resource id ='" + parentOf +
                                               "' not found")
                    } else {
                        if (child.isPlatform()) {
                            failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                                       "No parent for platform ='" + parentOf + "'")
                        } else if (child.isServer()) {
                            resource = child.toServer().platform.resource
                        } else if (child.isService()) {
                            resource = child.toService().server.resource
                        }
                    }                }
            } catch (PermissionException e) {
                failureXml = getFailureXML(ErrorCode.PERMISSION_DENIED)
            }
        }

        renderXml() {
            out << ResourceResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                    out << getResourceXMLWithAlertDefinitions(user, resource, verbose, children)
                }
            }
        }
    }

    def find(params) {
        def agentId = params.getOne("agentId")?.toInteger()
        def prototype = params.getOne("prototype")
        def description = params.getOne("description")
        def children = params.getOne("children", "false").toBoolean()
        def verbose = params.getOne("verbose", "false").toBoolean()

        def resources = []
        def failureXml
        
        if (!agentId && !prototype && !description) {
            failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS)
        } else {
            if (agentId) {
                def agent = getAgent(agentId, null, null)
                if (!agent) {
                    failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                               "Agent id=" + agentId +
                                               " not found")
                } else {
                    def platforms = agent.platforms
                    for (platform in platforms) {
                        try {
                            resources.add(platform.checkPerms(operation: 'view', user:user))
                        } catch (PermissionException e) {
                            log.debug("Ignoring platform " + platform.name + " due to permissions.")
                        }
                    }
                }
            } else if (prototype) {
                def matching = resourceHelper.find('byPrototype': prototype)

                for (resource in matching) {
                    try {
                        resources.add(checkViewPermission(resource))
                    } catch (PermissionException e) {
                        log.debug("Ignoring resource " + resource.name + " due to permissions")
                    }
                }
            } else if (description) {
                // TODO: Move into HQ.
                def matching = []
                def session =  org.hyperic.hq.hibernate.SessionManager.currentSession()
                matching.addAll(session.createQuery(
                    "select p.resource from Platform p where p.description like '%${description}%'").list())
                matching.addAll(session.createQuery(
                    "select s.resource from Server s where s.description like '%${description}%'").list())
                matching.addAll(session.createQuery(
                    "select s.resource from Service s where s.description like '%${description}%'").list())

                for (resource in matching) {
                    try {
                        resources.add(checkViewPermission(resource))
                    } catch (PermissionException e) {
                        log.debug("Ignoring resource " + resource.name + " due to permissions")
                    }
                }
            } else {
                // Shouldn't happen
                failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS)
            }
        }

        renderXml() {
            out << ResourcesResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                    for (resource in resources.sort {a, b -> a.name <=> b.name}) {
                        out << getResourceXML(user, resource, verbose, children)
                    }
                }
            }
        }
    }

    def getParentResourcesByRelation(params) {
    	def name = params.getOne("name")
    	def prototype = params.getOne("prototype")
    	def resourceRelation = params.getOne("resourceRelation")
    	def hasChildren = params.getOne("hasChildren").toBoolean()
    	
    	def platforms = null
    	def failureXml
    	
    	if (!resourceRelation 
    			|| !resourceRelation.equals(AuthzConstants.ResourceEdgeNetworkRelation)) {
    		failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS)    		
    	} else {
    		platforms = resourceHelper.findParentPlatformsByNetworkRelation(prototype, name, Boolean.valueOf(hasChildren))
    	}
    	
    	renderXml() {
    		ResourcesResponse() {
    			if (failureXml) {
                    out << failureXml
                } else {    			
    				out << getSuccessXML()
    				for (platform in platforms.sort {a, b -> a.name <=> b.name}) {
                		out << getResourceXML(user, platform.resource, Boolean.FALSE, Boolean.FALSE)
                	}
                }
    		}
    	}
    }
    
    def getResourcesByNoRelation(params) {
    	def name = params.getOne("name")
    	def prototype = params.getOne("prototype")
    	def resourceRelation = params.getOne("resourceRelation")
    	
    	def platforms = null
    	def failureXml
    	
    	if (!resourceRelation 
    			|| !resourceRelation.equals(AuthzConstants.ResourceEdgeNetworkRelation)) {
    		failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS)    		
    	} else {
    		platforms = resourceHelper.findPlatformsByNoNetworkRelation(prototype, name)
    	}
    	
    	renderXml() {
    		ResourcesResponse() {
    			if (failureXml) {
                    out << failureXml
                } else {    			
    				out << getSuccessXML()
    				for (platform in platforms.sort {a, b -> a.name <=> b.name}) {
                		out << getResourceXML(user, platform.resource, Boolean.FALSE, Boolean.FALSE)
                	}
                }
    		}
    	}
    }
    
    def getResourceEdges(params) {
    	def resourceRelation = params.getOne("resourceRelation")
    	def id = params.getOne("id")?.toInteger()
    	def prototype = params.getOne("prototype")
    	def name = params.getOne("name")
    	
    	def parent = null
    	def edges = []
    	def failureXml
    	
    	if (!resourceRelation)  {
    		failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS)
    	} else {
    		if (id) {
    			parent = getResource(id)
    			if (!parent) {
    				failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
    										   "Resource id=" + id +
    										   " not found")
    			} else {
    				edges = resourceHelper.findResourceEdges(resourceRelation, parent)
    			}
    		} else {
    			edges = resourceHelper.findResourceEdges(resourceRelation, prototype, name)
    		}
    	}

        renderXml() {
            out << ResourceEdgesResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                    if (edges.size() > 0) {
                    	if (parent) {
                    		out << getResourceEdgeGroupingXML(resourceRelation, 
                    						  	  		  	  parent, 
                    						  	  		  	  edges)
                    	} else {
                    		out << getResourceEdgeXML(edges)
                    	}
                    }
                }
            }
        }
    }
    
    // TODO: ResourceConfig does not properly handle unchanged configs.. 
    private configsEqual(existingConfig, newConfig) {
        def config = [:] + newConfig // Don't modify callers map
        existingConfig.each { k, v ->
            if (config.containsKey(k) && config[k] == v.value) {
                config.remove(k)
            }
        }
        return config.size() == 0;
    }
    
    private syncResource(xmlResource, parent) {

        def id   = xmlResource.'@id'?.toInteger()
        def name = xmlResource.'@name'
        def description = xmlResource.'@description'
        def location = xmlResource.'@location'

        def config = [name: name,
                      description: description,
                      location: location]
        
        xmlResource['ResourceConfig'].each {
            // Do not set configs for empty keys
            if (it.'@value' && it.'@value'.length() > 0) {
                config[it.'@key'] = it.'@value'
            }
        }
        
        xmlResource['ResourceProperty'].each {
            config[it.'@key'] = it.'@value'
        }

        if (!name) {
            return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                 "Resource name not given")
        }

        def xmlPrototype = xmlResource['ResourcePrototype']
        if (!xmlPrototype) {
            return getFailureXML(ErrorCode.INVALID_PARAMETERS ,
                                 "Resource prototype not given for " + name)
        }

        def prototype = resourceHelper.find(prototype: xmlPrototype.'@name')

        if (!prototype) {
            return getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                 "No ResourcePrototype found for " +
                                 name)
        }
        
        def resource = null
        if (id) {
            resource = getResource(id)
        }

        if (!resource) {
            if (parent) {
                // If parent is defined, look through existing children
                def matches = parent.getViewableChildren(user).grep { it.name == name }
                log.info "Found " + matches.size() + " matches for " + name
                if (matches.size() == 1) {
                    resource = matches[0]
                } else if (matches.size() > 1) {
                    return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                         "Found multiple matches for resource " + name)
                }
            } else {
                // Assume platform
                def fqdn = xmlResource['ResourceInfo'].find { it.'@key' == PROP_FQDN }
                if (fqdn) {
                	resource = resourceHelper.find('byFqdn':fqdn.'@value')
                } else {
                	resource = resourceHelper.find('platform':name)
                }
            }
        }

        if (resource) {
            // Add special configurations from ResourceInfo
            if (prototype.isPlatformPrototype()) {
                def fqdn = xmlResource['ResourceInfo'].find { it.'@key' == PROP_FQDN }
                if (!fqdn) {
                    return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                         "No FQDN given for " + name)
                } else {
                    config.put(PROP_FQDN, fqdn.'@value')
                }
                
                // Add agent info
        		def xmlAgent = xmlResource['Agent']        		
        		if (xmlAgent) {
        			def agentId = xmlAgent[0].'@id'?.toInteger()
                	def agent = getAgent(agentId, null, null)
                	if (!agent) {
                    	return getFailureXML(ErrorCode.OBJECT_NOT_FOUND ,
                                         "Unable to find agent id=" + agentId)
                	} else {
                		config.put(PROP_AGENT_ID, agentId)
                	}
                }
            } else if (prototype.isServerPrototype()) {
                def aiid = xmlResource['ResourceInfo'].find {
                    it.'@key' == PROP_AIIDENIFIER
                }
                if (aiid) {
                    config.put(PROP_AIIDENIFIER, aiid.'@value')
                }

                def installpath = xmlResource['ResourceInfo'].find {
                    it.'@key' == PROP_INSTALLPATH
                }
                if (installpath) {
                    config.put(PROP_INSTALLPATH, installpath.'@value')
                }
            } else if (prototype.isServicePrototype()) {
                def aiid = xmlResource['ResourceInfo'].find {
                    it.'@key' == PROP_AIIDENIFIER
                }
                if (aiid) {
                    config.put(PROP_AIIDENIFIER, aiid.'@value')
                }
            }

            def existingConfig = resource.getConfig()
            // 2nd pass over configuration to unset any variables that
            // may already exist in the existing config, but are empty in
            // the configuration being set.
            xmlResource['ResourceConfig'].each {
                if ((it.'@value' && it.'@value'.length() > 0) ||
                    (it.'@value' != null && !it.'@value'.equals(existingConfig[it.'@key']?.value))) {
                    config[it.'@key'] = it.'@value'
                }
            }

            // Update
            if (!configsEqual(existingConfig, config)) {
                try {
                    resource.setConfig(config, user)
                } catch (Throwable t) {
                    String cause = getCause(t)
                    return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                         "Error updating '" + name + "': " +
                                         cause)
                }
            }
        } else {
            // Create
            if (prototype.isPlatformPrototype()) {
                parent = resourceHelper.findRootResource()
                def xmlAgent = xmlResource['Agent']
                def agent = getAgent(xmlAgent[0].'@id'?.toInteger(),
                                     xmlAgent[0].'@address',
                                     xmlAgent[0].'@port'?.toInteger())
                if (!agent) {
                    return getFailureXML(ErrorCode.OBJECT_NOT_FOUND ,
                                         "Unable to find agent id=" + xmlAgent[0].'@id' +
                                         " address=" + xmlAgent[0].'@address' +
                                         " port=" + xmlAgent[0].'@port')
                }

                def fqdn = xmlResource['ResourceInfo'].find { it.'@key' == PROP_FQDN }
                if (!fqdn) {
                    return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                         "No FQDN given for " + name)
                } else {
                    config.put(PROP_FQDN, fqdn.'@value')
                }

                def xmlIps = xmlResource['Ip']
                def ips = []

                xmlIps.each { ip ->
                   ips << [address: ip.'@address', netmask: ip.'@netmask', mac: ip.'@mac']
                }

                try {
                    resource = prototype.createInstance(parent, name,
                                                        user, config, agent, ips)
                } catch (Throwable t) {
                    String cause = getCause(t)
                    log.warn("HQPI WARN: Error creating resource", t)
                    return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                         "Error creating '" + name + "':" +
                                         cause);
                }

            } else if (prototype.isServerPrototype()) {
                
                try {
                    def aiid = xmlResource['ResourceInfo'].find {
                        it.'@key' == PROP_AIIDENIFIER
                    }
                    if (aiid) {
                        config.put(PROP_AIIDENIFIER, aiid.'@value')
                    }

                    def installpath = xmlResource['ResourceInfo'].find {
                        it.'@key' == PROP_INSTALLPATH
                    }
                    if (installpath) {
                        config.put(PROP_INSTALLPATH, installpath.'@value')
                    }

                    resource = prototype.createInstance(parent, name,
                                                        user, config)
                } catch (Throwable t) {
                    String cause = getCause(t)
                    log.warn("HQPI WARN: Error creating resource", t)
                    return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                         "Error creating '" + name + "':" +
                                         cause);
                }
            } else if (prototype.isServicePrototype()) {

                try {
                    def aiid = xmlResource['ResourceInfo'].find {
                        it.'@key' == PROP_AIIDENIFIER
                    }
                    if (aiid) {
                        config.put(PROP_AIIDENIFIER, aiid.'@value')
                    }
                    resource = prototype.createInstance(parent, name,
                                                        user, config)  
                } catch (Throwable t) {
                    String cause = getCause(t)
                    log.warn("HQPI WARN: Error creating resource", t)
                    return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                         "Error creating '" + name + "':" +
                                         cause);
                }
            } else {
                return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                     "Invalid prototype=" + prototype.name)
            }
        }

        def xmlChildren = xmlResource['Resource']
        for (xmlChild in xmlChildren) {
            def res = syncResource(xmlChild, resource)
            if (res != null) {
                return res  // Exit early on errors.
            }
        }

        return null
    }



    def sync1(params) {

        def failureXml = null
        def syncRequest = new XmlParser().parseText(getPostData())

        for (xmlResource in syncRequest['Resource']) {
            failureXml = syncResource(xmlResource, null)
            if (failureXml != null) {
                break;
            }
        }

        renderXml() {
            StatusResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                }
            }
        }
    }




    def syncResourceEdges(params) {

        def failureXml = null
        def syncRequest = new XmlParser().parseText(getPostData())

        for (xmlResourceEdge in syncRequest['ResourceEdge']) {
            failureXml = updateResourceEdges("sync", xmlResourceEdge)
            if (failureXml != null) {
                break;
            }
        }

        renderXml() {
            StatusResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                }
            }
        }
    }
        
    def createResourceEdges(params) {

        def failureXml = null
        def syncRequest = new XmlParser().parseText(getPostData())

        for (xmlResourceEdge in syncRequest['ResourceEdge']) {
            failureXml = updateResourceEdges("add", xmlResourceEdge)
            if (failureXml != null) {
                break;
            }
        }

        renderXml() {
            StatusResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                }
            }
        }
    }
    
    def deleteResourceEdges(params) {

        def failureXml = null
        def syncRequest = new XmlParser().parseText(getPostData())

        for (xmlResourceEdge in syncRequest['ResourceEdge']) {
            failureXml = updateResourceEdges("remove", xmlResourceEdge)
            if (failureXml != null) {
                break;
            }
        }

        renderXml() {
            StatusResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                }
            }
        }    
    }

    def deleteAllResourceEdges(params) {
    	def resourceRelation = params.getOne("resourceRelation")
        def id = params.getOne("id")?.toInteger()
        def resource = null
        def failureXml = null
        
    	if (!resourceRelation 
    			|| !resourceRelation.equals(AuthzConstants.ResourceEdgeNetworkRelation)) {
    		failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS)    		
    	} else {
    		if (id) {
    			resource = getResource(id)
    			if (!resource) {
    				failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
    										   "Resource id=" + id +
    										   " not found")
    			} else {
    				try {
    					resourceHelper.removeResourceEdges(resourceRelation, resource)
    				} catch (Exception e) {
    					log.error("Error removing resource edges", e)
    					failureXml = getFailureXML(ErrorCode.UNEXPECTED_ERROR)
    				}
    			}
    		}
    	}
                
        renderXml() {
            StatusResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                }
            }
        }   	
    }
        
    private updateResourceEdges(syncType, xmlResourceEdge) {
    	def relation = xmlResourceEdge.'@relation'                          
        def xmlResourceFrom = xmlResourceEdge['ResourceFrom']
        def xmlResourceTo = xmlResourceEdge['ResourceTo']
        def xmlResource = null
        def resourceFrom = null
        def resourceTo = null
        def parent = null
        def children = []

        xmlResource = xmlResourceFrom['Resource'].get(0)
        resourceFrom = getResource(xmlResource.'@id'?.toInteger())
        
        if (resourceFrom) {
        	parent = AppdefUtil.newAppdefEntityId(resourceFrom)
        } else {
           	return getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                           "Unable to find resource with id = " +
                                           xmlResource.'@id')
        }
        
		xmlResourceTo['Resource'].each {
            resourceTo = getResource(it.'@id'?.toInteger())
            if (resourceTo) {
            	children << AppdefUtil.newAppdefEntityId(resourceTo)
            } else {
            	return getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                           "Unable to find resource with id = " +
                                           it.'@id')
        	}
        }
                
        try {
    		if (syncType.equals("add")) {
    			resourceHelper.createResourceEdges(relation, 
    										   	   parent, 
    										   	   (AppdefEntityID[]) children.toArray(),
    										   	   false)
    		} else if (syncType.equals("remove")) {
    			resourceHelper.removeResourceEdges(relation, 
    										   	   parent, 
    										   	   (AppdefEntityID[]) children.toArray())    		
    		} else if (syncType.equals("sync")) {
    			resourceHelper.createResourceEdges(relation, 
    										   	   parent, 
    										   	   (AppdefEntityID[]) children.toArray(),
    										   	   true)
    		}
    	} catch (PermissionException p) {
            return getFailureXML(ErrorCode.PERMISSION_DENIED)
    	} catch (ResourceEdgeCreateException r)  {
    		return getFailureXML(ErrorCode.INVALID_PARAMETERS, r.getMessage())
    	} catch (IllegalArgumentException i)  {
    		return getFailureXML(ErrorCode.INVALID_PARAMETERS, i.getMessage())
    	} catch (Exception e) {
    		return getFailureXML(ErrorCode.UNEXPECTED_ERROR, e.getMessage())
    	}
    	return null
	}

    // Walk the Resource tree ensuring all resources exist.
    private ensureResourcesExist(xmlResource) {
        def resource = getResource(xmlResource.'@id'?.toInteger())
        if (!resource) {
            return getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                           "Unable to find resource with id = " +
                                           xmlResource.'@id')
        }

        for (xmlChild in xmlResource['Resource']) {
            def result = ensureResourcesExist(xmlChild)
            if (result != null) {
                return result
            }
        }

        return null
    }

    // Uses sync(), but does extra checks to ensure the resource exists.
    def update(params) {
        def updateRequest = new XmlParser().parseText(getPostData())
        def xmlResources = updateRequest['Resource']
        def failureXml = null

        if (!xmlResources) {
            failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                       "Resource not given to update")
        } else if (xmlResources.size() != 1) {
            failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                       "Single resource not passed to update")
        } else {
            def xmlResource = xmlResources[0]

            failureXml = ensureResourcesExist(xmlResource)

            if (!failureXml) {
                failureXml = syncResource(xmlResource, null)
            }
        }

        renderXml() {
            StatusResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                }
            }
        }        
    }

    def delete(params) {
        def id = params.getOne("id")?.toInteger()
        def resource = getResource(id)

        if (!resource) {
            renderXml() {
                StatusResponse() {
                    out << getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                         "Resource id=" + id + " not found")
                }
            }
            return
        }

        try {
            resource.remove(user)
        } catch (Exception e) {
            log.error("Error removing resource", e)
            renderXml() {
                StatusResponse() {
                    out << getFailureXML(ErrorCode.UNEXPECTED_ERROR, 
                    					 "Error removing resource: " + e.getMessage())
                }
            }
            return
        }

        renderXml() {
            StatusResponse() {
                out << getSuccessXML()
            }
        }
    }

    def move(params) {
        def targetId = params.getOne("targetId")?.toInteger()
        def destinationId = params.getOne("destinationId")?.toInteger()

        def failureXml = null
        def target = getResource(targetId)
        if (!target) {
            failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                       "Unable to find target resource with " +
                                       "id =" + targetId)
        }

        def destination = getResource(destinationId)
        if (!destination) {
            failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                       "Unable to find destination resource with " +
                                       "id =" + destinationId)
        }

        if (failureXml) {
            renderXml() {
                StatusResponse() {
                    out << failureXml
                }
            }
            return
        }

        try {
            target.moveTo(user, destination)
        } catch (VetoException e) {
            failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                       e.getMessage())
        } catch (PermissionException e) {
            failureXml = getFailureXML(ErrorCode.PERMISSION_DENIED)
        }

        renderXml() {
            StatusResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                }
            }
        }
    }
}
