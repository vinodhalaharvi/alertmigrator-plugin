import org.hyperic.hq.hqu.rendit.HQUPlugin


class Plugin extends HQUPlugin {

    void initialize(File pluginDir) {
        super.initialize(pluginDir)
        addAdminView(true, '/api/index.hqu', 'AlertMigrator Web Services Api')
    }
}

