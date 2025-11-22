# E-Commerce Flask Application

A complete e-commerce web application with user authentication, product management, shopping cart, order processing, and review system.

## Quick Start

### 1. Install Python
Make sure Python 3.7+ is installed on your system.

### 2. Run Setup
```bash
# Windows
setup.bat

# Linux/Mac
chmod +x setup.sh
./setup.sh
```

### 3. Start Application
```bash
# Windows
run.bat

# Linux/Mac
python app.py
```

### 4. Access Application
Open browser and go to: `http://localhost:5000`

## Default Login Credentials

**Admin Account:**
- Email: `admin@ecommerce.com`
- Password: `admin123`

**User Account:**
- Email: `user@ecommerce.com` 
- Password: `user123`

## Features

- ✅ User Registration & Authentication
- ✅ Product Catalog with Search
- ✅ Shopping Cart & Checkout
- ✅ Order Management
- ✅ Admin Dashboard
- ✅ Product Reviews & Ratings
- ✅ Stock Management
- ✅ Multiple Payment Methods (Card/UPI/COD)
- ✅ Discount Coupons (SAVE10, SAVE20, WELCOME)

## Project Structure

```
ecommerce-app/
├── app.py              # Main application
├── setup_data.py       # Database initialization
├── requirements.txt    # Dependencies
├── data/              # Excel database files
├── static/            # CSS & Images
├── templates/         # HTML templates
└── uploads/           # File uploads
```

## Troubleshooting

If you encounter issues:
1. Ensure Python 3.7+ is installed
2. Run `pip install -r requirements.txt` manually
3. Delete `data/` folder and restart to reset database
4. Check if port 5000 is available

## Support

For issues, check the console output for error messages.