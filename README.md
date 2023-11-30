# My Web Application

This repository contains a web application I have created that you can easily set up using Docker.

## Prerequisites

Before you begin, make sure you have [Docker](https://www.docker.com/get-started) installed on your system.

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/rafhigh/IKT222_Assignment-3-User_Authentication.git
cd /IKT222_Assignment-3-User_Authentication
```

### 2. Build the docker image

```bash
docker build -t webapp:latest .
```


### 3. Run the docker container

```bash
docker run -d -p 5000:5000 webapp:latest
```

### 4. Access the web application
Open your web browser and navigate to http://localhost:5000 or http://0.0.0.0:5000 to view the running application.

