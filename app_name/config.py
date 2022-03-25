import os

# General
PRODUCT_NAME = "Bisa LSP"
PRODUCT_ENVIRONMENT = "DEV"  # DEV/PROD

IS_USE_VENV = "YES"  # YES/NO
VENV_FOLDER_PATH = os.path.abspath(os.path.join(
    __file__, "../../../venv_app_name")) + "/"  # Just Change value after __file__,

# JWT
JWT_SECRET_KEY = "anaksekolahid"
JWT_HEADER_TYPE = "JWT"

# Database
DB_NAME = "db_anaksekolah"
DB_USER = "root"
DB_PASSWORD = ""
DB_HOST = "localhost"

# URL
BACKEND_BASE_URL = "https://localhost:20000/"
