import axios from "axios";
import { alert } from "~/composables/use-toast";
import { readTokenCookie, writeTokenCookie } from "~/composables/use-token-cookie";
import { isSafeRedirectTarget } from "~/lib/validators/redirect";

declare module "axios" {
  interface AxiosRequestConfig {
    suppressAlert?: boolean;
  }
}

export default defineNuxtPlugin(() => {
  const tokenName = useRuntimeConfig().public.AUTH_TOKEN;
  const axiosInstance = axios.create({
    // timeout removed to allow backend to handle timeouts
    baseURL: "/", // api calls already pass with /api
    withCredentials: true,
  });

  axiosInstance.interceptors.request.use(
    (config) => {
      const token = readTokenCookie(tokenName);
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    },
    (error) => {
      return Promise.reject(error);
    },
  );

  // Add response interceptor
  axiosInstance.interceptors.response.use(
    (response) => {
      if (response?.data?.message && !response.config?.suppressAlert) alert.info(response.data.message as string);
      return response;
    },
    (error) => {
      if (error?.response?.data?.detail?.message) {
        alert.error(error.response.data.detail.message as string);
      };

      // If we receive a 401 Unauthorized response, clear the token cookie and redirect to login
      if (error?.response?.status === 401) {
        // If the token is not set, we may just be an unauthenticated user using the wrong API, so don't redirect
        if (readTokenCookie(tokenName)) {
          writeTokenCookie(tokenName, null);

          // Disable beforeunload warnings to prevent "Are you sure you want to leave?" popups
          window.onbeforeunload = null;

          const target = window.location.pathname + window.location.search;
          const redirect = isSafeRedirectTarget(target) && target !== "/login" ? `?redirect=${encodeURIComponent(target)}` : "";
          window.location.href = `/login${redirect}`;
        }
      }

      return Promise.reject(error);
    },
  );

  return {
    provide: {
      axios: axiosInstance,
    },
  };
});
