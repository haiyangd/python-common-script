 def _run_upgrade(self):
        self._logger.info("hooks: %s" % self._options.skip_existing_hooks)
        self._python_lib = glob.glob("%s/rootfs/usr/lib/python*"
                                     % self._tmp_dir)
        if not self._python_lib:
            raise RuntimeError("Unable to determine python path")
        self._python_lib = self._python_lib[0]
        sys.path.insert(0, self._python_lib + "/site-packages/")
        self._tmp_python_path = "%s/site-packages/ovirtnode" \
            % self._python_lib
        shutil.copytree(self._tmp_python_path, self._ovirtnode_dir)
        # import install and ovirtfunctions modules from new image
        f, filename, description = imp.find_module(
            'install',
            [self._ovirtnode_dir],
        )
        install = imp.load_module(
            'install',
            f,
            filename,
            description,
        )
        f, filename, description = imp.find_module(
            'ovirtfunctions',
            [self._ovirtnode_dir],
        )
        ovirtfunctions = imp.load_module(
            'ovirtfunctions',
            f,
            filename,
            description,
        )
        # log module detail for debugging
        self._logger.debug(install)
        import install
        import ovirtfunctions as _functions_new
        install._functions = _functions_new
        upgrade = install.Install()
        self._logger.propagate = True
        self._logger.info("Installing Bootloader")
        if not upgrade.ovirt_boot_setup():
            raise RuntimeError("Bootloader Installation Failed")
            
