# Stage 1: Build the application
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS builder

WORKDIR /usr/src/app

# Copy project file and restore dependencies
COPY TaskWizardMcpServer.csproj ./
RUN dotnet restore

# Copy source code and build
COPY . ./
RUN dotnet publish -c Release -o /app/publish --no-restore

# Stage 2: Create a smaller runtime image
FROM mcr.microsoft.com/dotnet/aspnet:9.0

WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/* && \
    groupadd -g 1000 taskwiz && \
    useradd -u 1000 -g taskwiz -s /usr/sbin/nologin -M taskwiz

COPY --from=builder /app/publish .
RUN chown -R taskwiz:taskwiz /app

ENV ASPNETCORE_URLS="http://+:3001"

# Entra authentication (always required)
# ENV TW_ENTRA_TENANT_ID=""
# ENV TW_ENTRA_AUDIENCE=""
# ENV TW_ENTRA_ISSUER=""

# Go API server URL for proxying requests
ENV TW_API_URL="http://apiserver:2021"

EXPOSE 3001

USER taskwiz

ENTRYPOINT ["dotnet", "TaskWizardMcpServer.dll"]
