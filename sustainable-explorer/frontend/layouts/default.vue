<template>
    <div class="flex min-h-screen">
        <AppSidebar />
        <div class="flex flex-1 flex-col overflow-auto">
            <AppTopbar />
            <main class="flex-1">
                <div class="container mx-auto p-6">
                    <slot />
                </div>
            </main>
        </div>
    </div>
</template>
