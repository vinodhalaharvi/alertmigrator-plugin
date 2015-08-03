import org.hyperic.hq.context.Bootstrap;
import org.hyperic.hq.hqapi1.ErrorCode;


import org.hyperic.hq.measurement.server.session.DataPoint as DP
import org.hyperic.hq.measurement.server.session.MeasurementInserterHolder;

class MetricdataController extends ApiController {

    private Closure getMetricDataXML(r) {
        { doc ->
            MetricData(resourceId: r.resource.id,
                       resourceName: r.resource.name,
                       metricId: r.metric.id,
                       metricName: r.metric.template.name) {
                // TODO: Backend does not always return data in asending order
                for (dp in r.data.sort {a, b -> a.timestamp <=> b.timestamp}) {
                    DataPoint(timestamp : dp.timestamp,
                              value     : dp.value)
                }
            }
        }
    }

    private Closure getLastMetricDataXML(r) {
        { doc ->
            LastMetricData(resourceId: r.resource.id,
                       resourceName: r.resource.name,
                       metricId: r.metric.id,
                       metricName: r.metric.template.name) {
                if (!r.data) {
                    log.warn("No data found for metric id=" + r.metric.id)
                } else {
                    DataPoint(timestamp : r.data.timestamp,
                              value     : r.data.value)
                }
            }
        }
    }

	private Closure getMetricDataSummaryXML(resource, metricCategory, summary) {
		{ doc ->
			MetricDataSummary(resourceId: resource.id,
							  resourceName: resource.name,
							  metricTemplateId: summary.templateId,
							  metricName: summary.label,
							  units: summary.units,
							  category: metricCategory,
							  startTime: summary.beginTimeFrame,
							  endTime: summary.endTimeFrame,
							  minMetric: summary.minMetric.value,
							  maxMetric: summary.maxMetric.value,
							  avgMetric: summary.avgMetric.value,
							  lastMetric: summary.lastMetric.value)
		}
	}
	
    /**
     * Validate metric parameters, returning a Closure representing the error
     * or null if the parameters are valid
     */
    private Closure validateParameters(metricIds, start, end) {

        if (start == null) {
            return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                 "Start time not given")
        }
        if (end == null) {
            return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                 "End time not given")
        }
        if (start < 0) {
            return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                 "Start time must be >= 0")
        }
        if (end < start) {
            return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                 "End time cannot be < start time")
        }
        return validateParameters(metricIds)
    }

    /**
     * Validate metric parameters, returning a Closure representing the error
     * or null if the parameters are valid
     */
    private Closure validateParameters(metricIds) {
        if (metricIds == null || metricIds.size() == 0) {
            return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                 "Metric id not given")
        }

        for (mid in metricIds) {
            if (!mid) {
                return getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                     "Metric id not given")
            }
            def metric = metricHelper.findMeasurementById(mid)
            if (!metric) {
                return getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                     "Metric id " + mid + " not found")
            }
        }
        return null
    }

    def get(params) {
        def metricId = params.getOne("id")?.toInteger()
        def start = params.getOne("start")?.toLong()
        def end = params.getOne("end")?.toLong()

        def failureXml = validateParameters([metricId], start, end)
        def metric = metricHelper.findMeasurementById(metricId)
        def data
        if (!failureXml) {
            try {
                data = metric.getData(start, end)
            } catch (Exception e) {
                log.error("UnexpectedError: " + e.getMessage(), e);
                failureXml = getFailureXML(ErrorCode.UNEXPECTED_ERROR)
            }
        }

        renderXml() {
            MetricDataResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    def result = [resource: metric.resource, metric: metric,
                                  data: data]
                    out << getSuccessXML()
                    out << getMetricDataXML(result)
                }
            }
        }
    }

    def getLast(params) {
        def metricId = params.getOne("id")?.toInteger()

        def failureXml = validateParameters([metricId])
        def metric = metricHelper.findMeasurementById(metricId)
        def data
        if (!failureXml) {
            try {
                data = metric.getLastDataPoint()
            } catch (Exception e) {
                log.error("UnexpectedError: " + e.getMessage(), e);
                failureXml = getFailureXML(ErrorCode.UNEXPECTED_ERROR)
            }
        }

        renderXml() {
            LastMetricDataResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    def result = [resource: metric.resource, metric: metric,
                                  data: data]
                    out << getSuccessXML()
                    out << getLastMetricDataXML(result)
                }
            }
        }
    }

    def getMulti(params) {
        def metricIds = params.get("id")*.toInteger()
        def start = params.getOne("start")?.toLong()
        def end = params.getOne("end")?.toLong()

        def failureXml = validateParameters(metricIds, start, end)

        def results = []
        
        if (!failureXml) {
            for (m in metricIds) {
                try {
                    // TODO: Switch to collections based API
                    def metric = metricHelper.findMeasurementById(m)
                    def data = metric.getData(start, end)
                    results << [resource: metric.resource,
                                metric: metric, data: data]
                } catch (Exception e) {
                    log.error("UnexpectedError: " + e.getMessage(), e);
                    failureXml = getFailureXML(ErrorCode.UNEXPECTED_ERROR)
                }
            }
        }

        renderXml() {
            MetricsDataResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                    for (result in results) {
                        out << getMetricDataXML(result)
                    }
                }
            }
        }
    }

    def getMultiLast(params) {
        def metricIds = params.get("id")*.toInteger()

        def failureXml = validateParameters(metricIds)

        def results = []

        if (!failureXml) {
            for (m in metricIds) {
                try {
                    def metric = metricHelper.findMeasurementById(m)
                    def data = metric.getLastDataPoint()
                    results << [resource: metric.resource,
                                metric: metric, data: data]
                } catch (Exception e) {
                    log.error("UnexpectedError: " + e.getMessage(), e);
                    failureXml = getFailureXML(ErrorCode.UNEXPECTED_ERROR)
                }
            }
        }

        renderXml() {
            LastMetricsDataResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                    for (result in results) {
                        out << getLastMetricDataXML(result)
                    }
                }
            }
        }
    }

    def getSummary(params) {
        def failureXml
        def summary
        def resource
        def resourceId = params.getOne("resourceId")?.toInteger()
        def start = params.getOne("start")?.toLong()
        def end = params.getOne("end")?.toLong()

        if (!resourceId) {
            failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
                                       "Resource id not given")
        } else {
            resource = getResource(resourceId)
            if (!resource) {
                failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                           "Unable to find resource id=" + resourceId)
            } else {
                try {
                    summary = resource.getMetricsSummary(user, start, end)                    
                } catch (Exception e) {
                    log.error("UnexpectedError: " + e.getMessage(), e)
                    failureXml = getFailureXML(ErrorCode.UNEXPECTED_ERROR)
                }
            }
        }

        renderXml() {
            MetricsDataSummaryResponse() {
                if (failureXml) {
                    out << failureXml
                } else {
                    out << getSuccessXML()
                    
                    summary.each {category, results ->
                    	results.each {item ->
                    		out << getMetricDataSummaryXML(resource, category, item)                    	
                    	}
                    }
                }
            }
        }
    }

    def put(params) {

        def inserter = null

        def failureXml = null

        def dataRequest = new XmlParser().parseText(getPostData())
        def metricId = dataRequest.'@metricId'?.toInteger()

        def metric = metricHelper.findMeasurementById(metricId)
        if (!metric) {
            failureXml = getFailureXML(ErrorCode.OBJECT_NOT_FOUND,
                                       "Unable to find metric with id = " +
                                       metricId)
        } else {
            try {
            	def points = []
            	for (dp in dataRequest["DataPoint"]) {
                	long ts = dp.'@timestamp'?.toLong()
                	double val = dp.'@value'?.toDouble()
                	points << createDataPoint(metric, val, ts)
            	}
            	log.info("Inserting " + points.size() + " metrics for " + metric.template.name)

            	if (metric.getTemplate().isAvailability()) {
            		inserter = Bootstrap.getBean(MeasurementInserterHolder.class).availDataInserter
            	} else {
                	inserter = Bootstrap.getBean(MeasurementInserterHolder.class).dataInserter
                }
                inserter.insertMetrics(points)
            } catch (IllegalArgumentException ia) {
            	failureXml = getFailureXML(ErrorCode.INVALID_PARAMETERS,
            							   ia.getMessage()) 
            } catch (Exception e) {
                failureXml = getFailureXML(ErrorCode.UNEXPECTED_ERROR,
                                           "Error inserting metrics: " +
                                           e.getMessage())
                log.warn("Error inserting metrics", e)
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
    
    private createDataPoint(metric, value, timestamp) {
    	if (metric.getTemplate().isAvailability()) {
    		if (value != 0.0 && value != 1.0 && value != -0.01) {
    			throw new IllegalArgumentException("Invalid availability data point: " + value)
    		}
    	}
    	
    	return new DP(metric.id, value, timestamp)
    }
}