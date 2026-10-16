namespace AppManager.Core {
    /**
     * An xdg-dbus-proxy instance standing between a sandboxed app and the message
     * buses, plus the rule set it enforces.
     *
     * The app never gets the real bus socket. It gets a socket this proxy listens on,
     * and the proxy forwards only what the rules allow. One process serves both buses:
     * the session bus for desktop services, the system bus for BlueZ and GeoClue2.
     *
     * Two descriptors do the coordination, both copied from what flatpak does:
     *
     *  - The **sync pipe**. The proxy holds the write end (--fd) and writes a single
     *    byte once it is listening; the supervisor blocks on the read end before
     *    starting the app, so the app can never race ahead of its own bus. The read end
     *    is then handed to the app's bwrap (--sync-fd), which holds it open for the
     *    sandbox's lifetime - so when the app dies the pipe closes and the proxy exits
     *    on its own. No supervision of the proxy is needed beyond that.
     *
     *  - The **args pipe** (--args), carrying the addresses and rules NUL-separated.
     *    Passing them this way keeps a long, revealing rule list out of
     *    /proc/<pid>/cmdline, where every process on the machine can read it.
     */
    public class SandboxDbusProxy {
        public string? session_socket { get; private set; default = null; }
        public string? system_socket { get; private set; default = null; }
        public string? a11y_socket { get; private set; default = null; }
        // The end to hand to the app's bwrap as --sync-fd.
        public int sync_read_fd { get; private set; default = -1; }

        private Posix.pid_t pid = 0;

        /**
         * Starts a proxy for `manifest`. Returns null when the proxy cannot be started,
         * which the supervisor turns into a fail-closed refusal: an app expecting a
         * filtered bus must not silently get none.
         *
         * `instance_id` names the sockets, so that concurrent launches of the same app
         * do not collide.
         */
        public static SandboxDbusProxy? start(SandboxManifest manifest, string instance_id) {
            var proxy_path = AppPaths.xdg_dbus_proxy_path;
            if (proxy_path == null) {
                return null;
            }

            var socket_dir = Path.build_filename(AppPaths.sandbox_runtime_dir, "dbusproxy");
            if (DirUtils.create_with_parents(socket_dir, 0700) != 0) {
                warning("Sandbox: cannot create %s: %s", socket_dir, Posix.strerror(Posix.errno));
                return null;
            }

            var self = new SandboxDbusProxy();
            var args = new Gee.ArrayList<string>();
            if (manifest.needs_session_bus()) {
                var session_address = host_session_bus_address();
                if (session_address == null) {
                    warning("Sandbox: no session bus address to proxy");
                    return null;
                }
                self.session_socket = Path.build_filename(socket_dir, "%s-session".printf(instance_id));
                args.add(session_address);
                args.add(self.session_socket);
                args.add("--filter");
                args.add_all(session_rules(manifest));
            }

            if (manifest.needs_system_bus()) {
                self.system_socket = Path.build_filename(socket_dir, "%s-system".printf(instance_id));
                args.add(Environment.get_variable("DBUS_SYSTEM_BUS_ADDRESS") ?? "unix:path=/run/dbus/system_bus_socket");
                args.add(self.system_socket);
                args.add("--filter");
                args.add_all(system_rules(manifest));
            }

            var a11y_address = manifest.accessibility && !manifest.full_session_bus ? a11y_bus_address() : null;
            if (a11y_address != null) {
                self.a11y_socket = Path.build_filename(socket_dir, "%s-a11y".printf(instance_id));
                args.add(a11y_address);
                args.add(self.a11y_socket);
                args.add("--filter");
                // Required, not cosmetic: at-spi addresses the registry by its unique
                // name, and without this the proxy never reports those name changes, so
                // none of the rules below can match.
                args.add("--sloppy-names");
                args.add_all(a11y_rules());
            }

            // A leftover socket from a supervisor that was killed would make bind fail.
            unlink_if_present(self.session_socket);
            unlink_if_present(self.system_socket);
            unlink_if_present(self.a11y_socket);

            int[] sync_fds = new int[2];
            if (Posix.pipe(sync_fds) != 0) {
                warning("Sandbox: cannot create bus proxy sync pipe: %s", Posix.strerror(Posix.errno));
                return null;
            }
            int args_fd = SandboxBwrap.content_fd(nul_separated(args));

            if (args_fd < 0) {
                Posix.close(sync_fds[0]);
                Posix.close(sync_fds[1]);
                return null;
            }

            var argv = build_argv(proxy_path, sync_fds[1], args_fd);

            var child = Posix.fork();
            if (child < 0) {
                warning("Sandbox: cannot fork the bus proxy: %s", Posix.strerror(Posix.errno));
                Posix.close(sync_fds[0]);
                Posix.close(sync_fds[1]);
                Posix.close(args_fd);
                return null;
            }
            if (child == 0) {
                clear_cloexec(sync_fds[1]);
                clear_cloexec(args_fd);
                Posix.close(sync_fds[0]);
                Posix.execvp(argv[0], argv);
                Posix.perror(argv[0]);
                Posix._exit(127);
            }

            self.pid = child;
            Posix.close(args_fd);
            // Our own copy of the write end has to go before the read below, or a proxy
            // that dies on startup would leave the read blocking on a pipe this process
            // is itself holding open.
            Posix.close(sync_fds[1]);

            uint8[] ready = new uint8[1];
            ssize_t got;
            while ((got = Posix.read(sync_fds[0], ready, 1)) < 0 && Posix.errno == Posix.EINTR) {
                // Retry: a signal arriving during startup is not a failure.
            }
            if (got != 1) {
                warning("Sandbox: the bus proxy did not come up");
                Posix.close(sync_fds[0]);
                self.stop();
                return null;
            }

            self.sync_read_fd = sync_fds[0];
            return self;
        }

        /**
         * Closes this process's copy of the sync pipe's read end. Must be called once
         * the app's bwrap has been forked and inherited it: while the supervisor still
         * holds a copy, the proxy cannot notice the app going away.
         */
        public void detach_sync_fd() {
            if (sync_read_fd >= 0) {
                Posix.close(sync_read_fd);
                sync_read_fd = -1;
            }
        }

        /**
         * Reaps the proxy. It normally exits by itself when the app's sandbox drops the
         * sync pipe, so this mostly just collects the corpse; a proxy still running
         * after the app is gone is asked to leave.
         */
        public void stop() {
            if (pid <= 0) {
                return;
            }
            int status;
            if (Posix.waitpid(pid, out status, Posix.WNOHANG) == 0) {
                Posix.kill(pid, Posix.Signal.TERM);
                while (Posix.waitpid(pid, out status, 0) < 0 && Posix.errno == Posix.EINTR) {
                    // Retry.
                }
            }
            pid = 0;
            unlink_if_present(session_socket);
            unlink_if_present(system_socket);
            unlink_if_present(a11y_socket);
        }

        /**
         * The proxy's command line. Nothing wraps it: the proxy is our own code doing
         * our own filtering, and it needs the host's own view of the buses it stands
         * in front of.
         */
        private static string[] build_argv(string proxy_path, int sync_fd, int args_fd) {
            return new string[] {
                proxy_path,
                "--fd=%d".printf(sync_fd),
                "--args=%d".printf(args_fd),
                null
            };
        }

        /**
         * Session-bus rules. Everything not listed is refused, including the services
         * that make sandbox escape trivial - systemd's StartTransientUnit above all.
         */
        public static Gee.ArrayList<string> session_rules(SandboxManifest manifest) {
            var rules = new Gee.ArrayList<string>();
            add_exact_rules(rules, manifest.session_rules);

            // The app has to be able to claim its own bus name: a GApplication whose
            // name request is refused decides it is a secondary instance and quits.
            // Both the exact name and its namespace are granted: the wildcard alone
            // does not match the exact name, and the exact name alone refuses helpers
            // that publish under a sub-name.
            foreach (var name in manifest.own_names) {
                rules.add("--own=" + name);
                rules.add("--own=%s.*".printf(name));
            }

            if (manifest.notifications) {
                rules.add("--talk=org.freedesktop.Notifications");
            }

            if (manifest.tray) {
                rules.add("--talk=org.kde.StatusNotifierWatcher");
                rules.add_all(status_notifier_item_names());
            }
            if (manifest.media_controls) {
                foreach (var name in manifest.media_names) {
                    rules.add("--own=" + name);
                    if (!name.has_suffix(".*")) rules.add("--own=" + name + ".*");
                }
            }
            if (manifest.keyring) {
                foreach (var name in KEYRING_NAMES) rules.add("--talk=" + name);
            }

            return rules;
        }

        // Secret Service (GNOME Keyring, KeePassXC, recent KWallet) and the KWallet
        // names Chromium and Electron call directly. Whole-service grants: the proxy
        // cannot filter on call arguments, so per-item access is not expressible.
        public const string[] KEYRING_NAMES = {
            "org.freedesktop.secrets",
            "org.kde.kwalletd5",
            "org.kde.kwalletd6"
        };

        // How far to enumerate tray-item names. The app is pid 2 in its own pid
        // namespace in the ordinary case; a few more cover an Electron app whose tray
        // lives in a forked helper, and a couple of item ids cover an app with more
        // than one indicator.
        private const int SNI_MAX_PID = 16;
        private const int SNI_MAX_ITEM = 4;

        /**
         * The bus names a StatusNotifierItem tray icon can claim.
         *
         * Two tray flavours exist. The object-path one hands the watcher a path on a
         * name the app already owns and so needs no rule of its own. The named one
         * registers org.kde.StatusNotifierItem-<pid>-<n> (libappindicator, Qt) or
         * org.freedesktop.StatusNotifierItem-<pid>-<n> (Chromium, so Electron). Electron
         * 43 drops its tray when that name is refused. The proxy's only wildcard is a
         * trailing ".*", which cannot match a name that varies before the last dot.
         *
         * "--own=org.kde.*" would match, but it would also let the app claim
         * org.kde.StatusNotifierWatcher itself, or a KDE wallet name. Enumerating the
         * handful of names actually reachable is uglier and strictly safer: the pid
         * namespace makes them small and predictable, since bwrap is pid 1 and the app
         * is pid 2.
         */
        private static Gee.ArrayList<string> status_notifier_item_names() {
            var rules = new Gee.ArrayList<string>();
            for (int pid = 2; pid <= SNI_MAX_PID; pid++) {
                for (int item = 1; item <= SNI_MAX_ITEM; item++) {
                    rules.add("--own=org.kde.StatusNotifierItem-%d-%d".printf(pid, item));
                    rules.add("--own=org.freedesktop.StatusNotifierItem-%d-%d".printf(pid, item));
                }
            }
            return rules;
        }

        /**
         * System-bus rules. Only spawned when a toggle needs it. NetworkManager has
         * an information-only permission; UPower is not exposed.
         */
        private static Gee.ArrayList<string> system_rules(SandboxManifest manifest) {
            var rules = new Gee.ArrayList<string>();
            add_exact_rules(rules, manifest.system_rules);
            if (manifest.bluetooth) {
                rules.add("--talk=org.bluez");
            }
            if (manifest.location) {
                rules.add_all(geoclue_rules());
            }
            if (manifest.network_info) {
                rules.add_all(network_info_rules());
            }
            return rules;
        }

        private static void add_exact_rules(Gee.ArrayList<string> output, string[] rules) {
            foreach (var rule in rules) {
                var colon = rule.index_of_char(':');
                if (colon <= 0) continue;
                var access = rule.substring(0, colon);
                var name = rule.substring(colon + 1);
                if (access in new string[] { "see", "talk", "own" }) output.add("--%s=%s".printf(access, name));
            }
        }

        public static Gee.ArrayList<string> network_info_rules() {
            var rules = new Gee.ArrayList<string>();
            const string service = "org.freedesktop.NetworkManager";
            var root = "/org/freedesktop/NetworkManager";
            // nm.dart initializes from the object manager, not GetDevices alone.
            rules.add("--call=%s=org.freedesktop.DBus.ObjectManager.GetManagedObjects@/org/freedesktop".printf(service));
            foreach (var member in new string[] { "InterfacesAdded", "InterfacesRemoved" }) {
                rules.add("--broadcast=%s=org.freedesktop.DBus.ObjectManager.%s@/org/freedesktop".printf(service, member));
            }
            foreach (var path in new string[] { root, root + "/*" }) {
                foreach (var member in new string[] { "Get", "GetAll" }) {
                    rules.add("--call=%s=org.freedesktop.DBus.Properties.%s@%s".printf(service, member, path));
                }
                rules.add("--broadcast=%s=org.freedesktop.DBus.Properties.PropertiesChanged@%s".printf(service, path));
            }
            foreach (var member in new string[] { "GetDevices", "GetAllDevices", "GetDeviceByIpIface" }) {
                rules.add("--call=%s=%s.%s@%s".printf(service, service, member, root));
            }
            // No Set, activation, Settings methods, secrets or wireless scans.
            return rules;
        }

        /**
         * GeoClue2, narrowed to the objects a client actually uses: the manager it asks
         * for a client object, and the client object itself, whose path is handed out at
         * runtime as /org/freedesktop/GeoClue2/Client/<n> with the fix hanging below it.
         * The trailing "/*" is a subtree match, so one rule covers a client and its
         * Location children.
         *
         * Deliberately not a bare --talk=org.freedesktop.GeoClue2: a rule with no path
         * or interface permits the whole service. --call already implies talk, which is
         * what lets the D-Bus-activated daemon start on the first call.
         *
         * LocationUpdated needs no rule of its own - geoclue emits it addressed to the
         * client rather than broadcast, and the proxy only filters signals with no
         * destination. PropertiesChanged is a real broadcast and does need one, or an
         * app relying on property caching never sees the fix arrive.
         */
        private static Gee.ArrayList<string> geoclue_rules() {
            var rules = new Gee.ArrayList<string>();
            foreach (var rule in new string[] {
                "--call=org.freedesktop.GeoClue2=org.freedesktop.GeoClue2.Manager.*@/org/freedesktop/GeoClue2/Manager",
                "--call=org.freedesktop.GeoClue2=org.freedesktop.DBus.Properties.*@/org/freedesktop/GeoClue2/Manager",
                "--call=org.freedesktop.GeoClue2=org.freedesktop.GeoClue2.Client.*@/org/freedesktop/GeoClue2/Client/*",
                "--call=org.freedesktop.GeoClue2=org.freedesktop.DBus.Properties.*@/org/freedesktop/GeoClue2/Client/*",
                "--broadcast=org.freedesktop.GeoClue2=org.freedesktop.DBus.Properties.PropertiesChanged@/org/freedesktop/GeoClue2/*"
            }) {
                rules.add(rule);
            }
            return rules;
        }

        /**
         * Accessibility-bus rules, taken from flatpak's own a11y proxy: enough for a
         * toolkit to publish its accessible tree and to hear which events something is
         * listening for, and nothing else.
         *
         * The a11y bus needs filtering as much as the session bus does. It is how a
         * screen reader reads every window on the desktop, so an app with a free run of
         * it can read other apps' contents and watch their keystrokes - which is why the
         * app is not simply handed the real socket.
         */
        private static Gee.ArrayList<string> a11y_rules() {
            var rules = new Gee.ArrayList<string>();
            foreach (var rule in new string[] {
                "--broadcast=org.a11y.atspi.Registry=org.a11y.atspi.Registry.EventListenerRegistered@/org/a11y/atspi/registry",
                "--broadcast=org.a11y.atspi.Registry=org.a11y.atspi.Registry.EventListenerDeregistered@/org/a11y/atspi/registry",
                "--call=org.a11y.atspi.Registry=org.a11y.atspi.Socket.Embed@/org/a11y/atspi/accessible/root",
                "--call=org.a11y.atspi.Registry=org.a11y.atspi.Socket.Unembed@/org/a11y/atspi/accessible/root",
                "--call=org.a11y.atspi.Registry=org.a11y.atspi.Registry.GetRegisteredEvents@/org/a11y/atspi/registry",
                "--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.GetKeystrokeListeners@/org/a11y/atspi/registry/deviceeventcontroller",
                "--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.GetDeviceEventListeners@/org/a11y/atspi/registry/deviceeventcontroller",
                "--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.NotifyListenersSync@/org/a11y/atspi/registry/deviceeventcontroller",
                "--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.NotifyListenersAsync@/org/a11y/atspi/registry/deviceeventcontroller"
            }) {
                rules.add(rule);
            }
            return rules;
        }

        /**
         * The accessibility bus's address. It is a bus of its own, not a service on the
         * session bus, so it has an address of its own: whatever the session already put
         * in the environment, or else the answer to org.a11y.Bus.GetAddress, which
         * starts at-spi-bus-launcher on the way if it is not running yet.
         *
         * Null when the session has no accessibility bus at all. That is not an error -
         * the app then starts without one, which is what happens outside a sandbox too.
         */
        public static string? a11y_bus_address() {
            var env = Environment.get_variable("AT_SPI_BUS_ADDRESS");
            if (env != null && env.strip() != "") {
                return env.strip();
            }
            try {
                var bus = Bus.get_sync(BusType.SESSION);
                var reply = bus.call_sync("org.a11y.Bus", "/org/a11y/bus", "org.a11y.Bus",
                                          "GetAddress", null, new VariantType("(s)"),
                                          DBusCallFlags.NONE, 5000);
                string address;
                reply.get("(s)", out address);
                return (address != null && address.strip() != "") ? address.strip() : null;
            } catch (Error e) {
                debug("Sandbox: no accessibility bus: %s", e.message);
                return null;
            }
        }

        /**
         * The real accessibility bus socket, for the full-session-bus case where no
         * proxy runs and there is nothing to filter with.
         */
        public static string? host_a11y_socket() {
            var address = a11y_bus_address();
            return address == null ? null : SandboxBwrap.socket_path_in(address);
        }

        /**
         * The address of the session bus to proxy. Uses DBUS_SESSION_BUS_ADDRESS as
         * given - it is an address, not a path, so abstract sockets work here even
         * though they could not be bind-mounted into the sandbox.
         */
        private static string? host_session_bus_address() {
            var address = Environment.get_variable("DBUS_SESSION_BUS_ADDRESS");
            if (address != null && address.strip() != "") {
                return address.strip();
            }
            var fallback = Path.build_filename(AppPaths.sandbox_runtime_base, "bus");
            if (GLib.FileUtils.test(fallback, FileTest.EXISTS)) {
                return "unix:path=%s".printf(fallback);
            }
            return null;
        }

        /**
         * The proxy's --args format: every argument followed by a NUL byte. Built as
         * bytes rather than a string, which would end at the first separator.
         */
        private static uint8[] nul_separated(Gee.List<string> items) {
            int total = 0;
            foreach (var item in items) {
                total += item.data.length + 1;
            }
            var result = new uint8[total];
            int offset = 0;
            foreach (var item in items) {
                foreach (var byte in item.data) {
                    result[offset++] = byte;
                }
                result[offset++] = 0;
            }
            return result;
        }

        private static void clear_cloexec(int fd) {
            int flags = Posix.fcntl(fd, Posix.F_GETFD);
            if (flags >= 0) {
                Posix.fcntl(fd, Posix.F_SETFD, flags & ~Posix.FD_CLOEXEC);
            }
        }

        private static void unlink_if_present(string? path) {
            if (path != null && GLib.FileUtils.test(path, FileTest.EXISTS)) {
                GLib.FileUtils.unlink(path);
            }
        }
    }
}
