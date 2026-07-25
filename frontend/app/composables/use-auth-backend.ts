import { ref, computed } from "vue";
import type { UserOut } from "~/lib/api/types/user";
import { clearAllStores } from "~/composables/store";
import { clearComposableCaches } from "~/composables/use-clear-composable-caches";
import { readTokenCookie, shouldRenewToken, writeTokenCookie } from "~/composables/use-token-cookie";

interface AuthData {
  value: UserOut | null;
}

interface AuthStatus {
  value: "loading" | "authenticated" | "unauthenticated";
}

interface AuthState {
  data: AuthData;
  status: AuthStatus;
  token: { readonly value: string | null | undefined };
  signIn: (credentials: FormData, options?: { redirect?: boolean }) => Promise<void>;
  signOut: (callbackUrl?: string) => Promise<void>;
  refresh: () => Promise<void>;
  getSession: () => Promise<void>;
  setToken: (token: string | null) => void;
  syncTokenFromCookie: () => void;
  renewSessionIfStale: () => Promise<void>;
}

const authUser = ref<UserOut | null>(null);
const authStatus = ref<"loading" | "authenticated" | "unauthenticated">("loading");

// The cookie is the source of truth, but it is mirrored here so that reads are synchronous and
// shared across every caller. `useCookie` can't be used for this: it binds `maxAge` when the ref
// is created, so it cannot give a 30 day token a 30 day cookie when TOKEN_TIME is shorter, and
// its writes land asynchronously — which previously let getSession() run before the new token
// was visible and report the user as logged out right after a successful sign-in.
const authToken = ref<string | null>(null);
let tokenLoaded = false;

export function resetAuth() {
  authUser.value = null;
  authStatus.value = "unauthenticated";
}

export const useAuthBackend = function (): AuthState {
  const { $axios } = useNuxtApp();
  const router = useRouter();

  const runtimeConfig = useRuntimeConfig();
  const tokenName = runtimeConfig.public.AUTH_TOKEN;

  /** Re-read the cookie, picking up sign-ins and sign-outs made in another tab. */
  function syncTokenFromCookie() {
    if (import.meta.client) {
      authToken.value = readTokenCookie(tokenName);
    }
  }

  if (!tokenLoaded) {
    tokenLoaded = true;
    syncTokenFromCookie();
  }

  function setToken(token: string | null) {
    authToken.value = token;
    if (import.meta.client) {
      writeTokenCookie(tokenName, token);
    }
  }

  function handleAuthError(error: any, redirect = false) {
    // Only clear token on auth errors, not network errors
    if (error?.response?.status === 401) {
      setToken(null);
      resetAuth();
      if (redirect) {
        router.push("/login");
      }
    }
  }

  async function getSession(): Promise<void> {
    if (!authToken.value) {
      authUser.value = null;
      authStatus.value = "unauthenticated";
      return;
    }

    authStatus.value = "loading";
    try {
      const { data } = await $axios.get<UserOut>("/api/users/self");
      authUser.value = data;
      authStatus.value = "authenticated";
    }
    catch (error: any) {
      console.error("Failed to fetch user session:", error);
      handleAuthError(error);
      authStatus.value = "unauthenticated";
    }
  }

  async function signIn(credentials: FormData): Promise<void> {
    authStatus.value = "loading";

    try {
      const response = await $axios.post("/api/auth/token", credentials, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      const { access_token } = response.data;
      setToken(access_token);
      await getSession();
    }
    catch (error) {
      authStatus.value = "unauthenticated";
      throw error;
    }
  }

  async function signOut(callbackUrl: string = ""): Promise<void> {
    try {
      await $axios.post("/api/auth/logout");
    }
    catch (error) {
      // Continue with logout even if API call fails
      console.warn("Logout API call failed:", error);
    }
    finally {
      setToken(null);
      resetAuth();

      // Clear all cached store data to prevent data leakage between users
      clearAllStores();

      // Clear cached composable refs to prevent data leakage between users
      clearComposableCaches();

      // Clear Nuxt's useAsyncData cache
      clearNuxtData();

      await router.push(callbackUrl || "/login");
    }
  }

  async function refresh(): Promise<void> {
    if (!authToken.value) return;

    try {
      const response = await $axios.get("/api/auth/refresh");
      const { access_token } = response.data;
      setToken(access_token);
      await getSession();
    }
    catch (error: any) {
      handleAuthError(error, true);
      throw error;
    }
  }

  /**
   * Slide the session forward.
   *
   * Without this the token's expiry is fixed at the moment of sign-in, so a user is logged out a
   * fixed window after they first logged in no matter how often they use the app. Renewing on
   * startup (and when the tab is refocused) means any visit inside the window extends it, which is
   * what keeps someone logged in indefinitely. Failures are swallowed: a renewal that can't reach
   * the server must not disturb a session whose token is still perfectly valid.
   */
  async function renewSessionIfStale(): Promise<void> {
    const token = authToken.value;
    if (!token || authStatus.value !== "authenticated" || !shouldRenewToken(token)) {
      return;
    }

    try {
      const response = await $axios.get("/api/auth/refresh");
      setToken(response.data.access_token);
    }
    catch (error: any) {
      console.debug("Session renewal skipped:", error);
    }
  }

  return {
    data: computed(() => authUser.value),
    status: computed(() => authStatus.value),
    token: computed(() => authToken.value),
    signIn,
    signOut,
    refresh,
    getSession,
    setToken,
    syncTokenFromCookie,
    renewSessionIfStale,
  };
};
