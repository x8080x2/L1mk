I will separate the Deployer logic for the Docker container while preserving the Main Application's routing for the VPS.

### 1. **Address Main Application Routing**
   - **Clarification**: The Main Application on your VPS uses **Nginx** (configured by the deployer) or **Apache** (via `.htaccess`), which points directly to `index.php`. It does **not** use `router.php`.
   - **Conclusion**: Changing the router used by Docker will **not** affect your live VPS site.

### 2. **Create Dedicated Docker Router (`router_deployer.php`)**
   - **Goal**: Create a specific router for the Docker container that *only* exposes the Deployer, without modifying the existing `router.php` (preserving local development for the page).
   - **Action**: Create `router_deployer.php` in the root:
     - **Redirect Root**: `/` -> `/deploy_tool/`.
     - **Allow**: Requests starting with `/deploy_tool/`.
     - **Block**: All other requests (returning 403 Forbidden), effectively hiding the "page" in the Render deployment.

### 3. **Update `Dockerfile`**
   - **Goal**: Tell Render to use the new restricted router.
   - **Action**: Change the `CMD` in `Dockerfile` to use `router_deployer.php` instead of `router.php`.

### 4. **Optimize Deployment Package (`deploy_tool/lib.php`)**
   - **Goal**: Ensure the deployer sends a clean, source-only package to the VPS.
   - **Action**: Update `is_file_needed` in `deploy_tool/lib.php` to:
     - **Exclude `vendor/`**: Dependencies are installed on the VPS.
     - **Exclude `Dockerfile` & `router_deployer.php`**: These are for the container only.
