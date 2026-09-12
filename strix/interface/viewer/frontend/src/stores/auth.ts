// Local stub of the strix-app auth store. The local viewer has no accounts:
// there is never a signed-in user and no feature is entitled, so every upsell
// CTA routes to the external cloud sign-up link.
interface AuthState {
  user: null;
  hasFeature: (feature: string) => boolean;
}

const STATE: AuthState = {
  user: null,
  hasFeature: () => false,
};

export function useAuthStore<T>(selector: (s: AuthState) => T): T {
  return selector(STATE);
}
