### Readme
Simple note application created with claude.ai and github integration.
Just clone the repository into a docker server and: docker-compose up -d --build

### Directory Structure
├── docker-compose.yml
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── database.py
│   ├── auth.py
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── notes.html
│   │   └── settings.html
│   └── static/
│       └── css/
│           └── style.css
└── Dockerfile
