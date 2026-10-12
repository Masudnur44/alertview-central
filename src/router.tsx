import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";
import { createRouter } from "@tanstack/react-router";
import { toast } from "sonner";
import { routeTree } from "./routeTree.gen";

// Server functions throw these codes when the session is missing or incomplete.
const AUTH_REDIRECTS: Record<string, string> = {
  UNAUTHENTICATED: "/auth",
  MFA_REQUIRED: "/auth/mfa",
  PENDING_APPROVAL: "/pending",
  MFA_ENROLLMENT_REQUIRED: "/account?setup=mfa",
};

export function handleAuthError(error: unknown): boolean {
  const msg = error instanceof Error ? error.message : String(error);
  const target = Object.entries(AUTH_REDIRECTS).find(([code]) => msg.includes(code))?.[1];
  if (target && typeof window !== "undefined") {
    if (!window.location.pathname.startsWith(target.split("?")[0]!)) window.location.assign(target);
    return true;
  }
  return false;
}

export const getRouter = () => {
  const queryClient = new QueryClient({
    queryCache: new QueryCache({ onError: (e) => void handleAuthError(e) }),
    mutationCache: new MutationCache({
      onError: (e) => {
        if (!handleAuthError(e)) toast.error(e instanceof Error ? e.message.replace(/^FORBIDDEN: /, "") : "Something went wrong");
      },
    }),
    defaultOptions: { queries: { retry: (n, e) => n < 2 && !handleAuthError(e), staleTime: 10_000 } },
  });

  return createRouter({
    routeTree,
    context: { queryClient },
    scrollRestoration: true,
    defaultPreloadStaleTime: 0,
  });
};
