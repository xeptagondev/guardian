/**
 * Route middleware for admin-only pages (/admin/**).
 *
 * Apply per-page via definePageMeta({ middleware: 'admin' }). Non-admins are
 * redirected home; unauthenticated visitors additionally get the sign-in modal.
 */
export default defineNuxtRouteMiddleware(async (to) => {
    const { authStatus, isAdmin, initAuth, openSignIn } = useAuth();

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
    if (!isAdmin.value) {
        return navigateTo('/');
    }
});
