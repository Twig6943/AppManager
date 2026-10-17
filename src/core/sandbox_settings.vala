namespace AppManager.Core {
    /**
     * GSettings for a sandbox behind the filtered bus. dconf writes go over D-Bus to
     * ca.desrt.dconf, which the proxy refuses, and GLib then reverts the value:
     * preferences never stick and a window size bound to a key snaps back. So the
     * sandbox uses GLib's keyfile backend in its private home, seeded from the host's
     * dconf on every launch. GLib's own read-only defaults layer would fit better, but
     * its path is fixed at /etc/glib-2.0/settings and /etc is the host's, read-only.
     */
    public class SandboxSettings : Object {
        private const string KEYFILE = "keyfile";
        // The host values the last seed wrote, to tell them from the app's own writes.
        private const string SEED = "host-seed";

        public static void seed(string home) {
            string dump;
            int status;
            try {
                // `dconf dump` prints the format the keyfile backend reads.
                Process.spawn_sync(null, { "dconf", "dump", "/" }, null,
                    SpawnFlags.SEARCH_PATH | SpawnFlags.STDERR_TO_DEV_NULL, null, out dump, null, out status);
            } catch (SpawnError e) {
                debug("Sandbox: no host dconf to seed settings from: %s", e.message);
                return;
            }
            if (status != 0) {
                debug("Sandbox: dconf dump failed (%d), settings not seeded", status);
                return;
            }
            try {
                if (!apply(home, dump)) {
                    warning("Sandbox: cannot seed settings under %s: %s", home, Posix.strerror(Posix.errno));
                }
            } catch (KeyFileError e) {
                warning("Sandbox: unreadable dconf dump: %s", e.message);
            }
        }

        public static bool apply(string home, string host) throws KeyFileError {
            int dir = open_settings_dir(home);
            if (dir < 0) {
                return false;
            }
            try {
                return write_at(dir, KEYFILE, merge(read_at(dir, KEYFILE), read_at(dir, SEED), host))
                    && write_at(dir, SEED, host);
            } finally {
                Posix.close(dir);
            }
        }

        /**
         * The host's values, except for keys the app wrote since the last seed (absent
         * from it, or different), which are kept.
         */
        public static string merge(string current, string previous, string host) throws KeyFileError {
            var result = new KeyFile();
            result.load_from_data(host, -1, KeyFileFlags.NONE);
            var app = load(current);
            var seeded = load(previous);
            foreach (var group in app.get_groups()) {
                foreach (var key in app.get_keys(group)) {
                    var value = app.get_value(group, key);
                    if (value != lookup(seeded, group, key)) {
                        result.set_value(group, key, value);
                    }
                }
            }
            return result.to_data();
        }

        private static KeyFile load(string data) {
            var file = new KeyFile();
            try {
                file.load_from_data(data, -1, KeyFileFlags.NONE);
            } catch (KeyFileError e) {
                return new KeyFile();
            }
            return file;
        }

        private static string? lookup(KeyFile file, string group, string key) {
            try {
                return file.has_group(group) && file.has_key(group, key) ? file.get_value(group, key) : null;
            } catch (KeyFileError e) {
                return null;
            }
        }

        // The home is app-writable: anchor every step to a directory fd and refuse
        // symlinks, so a planted link cannot redirect this host-side write.
        private static int open_settings_dir(string home) {
            int dir = Posix.open(home, Posix.O_RDONLY | Posix.O_DIRECTORY | Posix.O_NOFOLLOW | Posix.O_CLOEXEC);
            foreach (var part in new string[] { ".config", "glib-2.0", "settings" }) {
                if (dir < 0) break;
                if (Posix.mkdirat(dir, part, 0700) != 0 && Posix.errno != Posix.EEXIST) {
                    Posix.close(dir);
                    return -1;
                }
                int next = Posix.openat(dir, part, Posix.O_RDONLY | Posix.O_DIRECTORY | Posix.O_NOFOLLOW | Posix.O_CLOEXEC);
                Posix.close(dir);
                dir = next;
            }
            return dir;
        }

        private static string read_at(int dir, string name) {
            int fd = Posix.openat(dir, name, Posix.O_RDONLY | Posix.O_NOFOLLOW | Posix.O_NONBLOCK | Posix.O_CLOEXEC);
            if (fd < 0) {
                return "";
            }
            var data = new StringBuilder();
            Posix.Stat st = Posix.Stat();
            if (Posix.fstat(fd, out st) == 0 && Posix.S_ISREG(st.st_mode)) {
                var buf = new uint8[65536];
                ssize_t n;
                while ((n = Posix.read(fd, buf, buf.length)) > 0) {
                    data.append_len((string) buf, n);
                }
            }
            Posix.close(fd);
            return data.str;
        }

        // A fresh file renamed into place: a running instance never reads half of it.
        private static bool write_at(int dir, string name, string data) {
            var tmp = "." + name + ".new";
            Posix.unlinkat(dir, tmp, 0);
            int fd = Posix.openat(dir, tmp, Posix.O_CREAT | Posix.O_EXCL | Posix.O_WRONLY | Posix.O_NOFOLLOW | Posix.O_CLOEXEC, 0600);
            if (fd < 0) {
                return false;
            }
            size_t done = 0;
            while (done < data.length) {
                var n = Posix.write(fd, (uint8*) data + done, data.length - done);
                if (n <= 0) break;
                done += n;
            }
            Posix.close(fd);
            return done == data.length && Posix.renameat(dir, tmp, dir, name) == 0;
        }
    }
}
