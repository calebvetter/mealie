export default defineNuxtPlugin({
  async setup() {
    const auth = useAuthBackend();

    console.debug("Initializing auth plugin");
    await auth.getSession();
    console.debug("Auth plugin initialized");

    // Sliding session: every visit extends the login window, so an active user stays signed in.
    void auth.renewSessionIfStale();

    // A PWA or pinned tab can stay open for weeks without re-running this plugin, so check again
    // on refocus. This doubles as a resync for sign-ins/sign-outs made in another tab.
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState !== "visible") {
        return;
      }

      auth.syncTokenFromCookie();
      void auth.renewSessionIfStale();
    });
  },
});
