# =============================================================================
# Container Vulnerability Scanner - Dashboard
# =============================================================================
# Simple nginx-based container to serve the static dashboard
#
# Design Decisions:
# - Uses nginx:alpine for minimal footprint
# - Includes API proxy configuration for CORS handling
# - Static files only - no server-side processing needed
#
# Security Considerations:
# - Uses official nginx image (regularly updated)
# - Runs as non-root where possible
# - Only exposes necessary port
# =============================================================================

FROM nginx:alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy static files
COPY index.html /usr/share/nginx/html/index.html

# Expose port 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:80/ || exit 1

# Run nginx
CMD ["nginx", "-g", "daemon off;"]
