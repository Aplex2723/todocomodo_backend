# Use the official Python image as a base
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy only requirements.txt first to leverage Docker cache
COPY requirements.txt /app/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . /app

# Expose the port the app runs on
EXPOSE 80

# Set environment variables
ENV FLASK_APP=run.py
ENV FLASK_ENV=production

# Command to run the application
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:80", "--access-logfile", "-", "--error-logfile", "-", "--log-level", "debug", "run:app"]