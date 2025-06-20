# Use official Python base image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Copy requirements file into container
COPY requirements.txt ./

# Install dependencies
RUN pip install --upgrade pip --root-user-action=ignore && \
    pip install -r requirements.txt

# Copy the rest of the application files
COPY . .

# Run the application
CMD ["python", "Main.py"]
