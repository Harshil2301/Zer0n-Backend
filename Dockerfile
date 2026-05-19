FROM node:18-slim

# Install Google Chrome stable and dependent libraries for Puppeteer
RUN apt-get update \
    && apt-get install -y wget gnupg \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list' \
    && apt-get update \
    && apt-get install -y google-chrome-stable fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf libxss1 \
      --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Set Puppeteer environment configurations to use installed Google Chrome
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome-stable

# Setup app working directory
WORKDIR /app

# Copy dependency catalogs
COPY package*.json ./

# Install dependencies (ignoring development dependencies)
RUN npm ci --only=production

# Copy application source
COPY . .

# Expose server port
EXPOSE 5000

# Start script
CMD ["node", "server-simple.js"]
