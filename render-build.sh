#!/usr/bin/env bash
# exit on error
set -o errexit

# Install project dependencies
npm install

# Pre-install Chrome inside Render container for Puppeteer
echo "Downloading Chrome browser binary..."
npx puppeteer browsers install chrome
