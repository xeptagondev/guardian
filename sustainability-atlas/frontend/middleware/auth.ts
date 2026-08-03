/**
 * Route middleware for pages that require an authenticated user.
 *
 * Apply per-page via definePageMeta({ middleware: 'auth' }). Unauthenticated
 * visitors are redirected home; on the client the sign-in modal is opened so
 * they can authenticate without losing context.
 */
export default defineNuxtRouteMiddleware(async (to) => {
    const { authStatus, initAuth, openSignIn } = useAuth();

    if (authStatus.value === 'idle' || authStatus.value === 'checking') {
        await initAuth();
    }

    if (authStatus.value === 'unauthenticated') {
        const returnUrl = isSafeRedirect(to.fullPath) ? to.fullPath : '/';
        if (import.meta.client) openSignIn(returnUrl);
        return navigateTo({
            path: '/',
            query: returnUrl !== '/' ? { redirect: returnUrl } : undefined,
        });
    }
});
