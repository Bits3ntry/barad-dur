FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

# F5 packaging of the platform API: same checkout the CLI and console use;
# migrations run at container start (serve applies them before binding).
WORKDIR /platform
COPY . .
RUN pip install --no-cache-dir . && useradd --uid 1001 --system plat
USER 1001:1001
ENV PYTHONDONTWRITEBYTECODE=1 PLATFORM_DATABASE_URL_FILE=

# Barad's compose contract: digest-pinned base, no root, read-only code.
EXPOSE 8090
ENTRYPOINT ["barad-platform", "serve", "--host", "0.0.0.0", "--port", "8090"]
