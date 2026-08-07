import os
import sqlite3
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g
)
from werkzeug.security import generate_password_hash, check_password_hash

# ====================================================
# Flask Configuration
# ====================================================

app = Flask(__name__)
app.secret_key = 'ecommerce_secret_key_college_project'
DATABASE = 'db.sqlite'

# ====================================================
# Database Connection
# ====================================================

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ====================================================
# Database Initialization
# ====================================================

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Seller Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS seller (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seller_name TEXT NOT NULL,
                contact TEXT NOT NULL,
                address TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        
        # Buyer Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS buyer (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                buyer_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                address TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        
        # Product Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS product (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seller_id INTEGER NOT NULL,
                product_name TEXT NOT NULL,
                price REAL NOT NULL,
                description TEXT NOT NULL,
                color TEXT NOT NULL,
                size TEXT NOT NULL,
                rating INTEGER NOT NULL,
                FOREIGN KEY (seller_id) REFERENCES seller (id)
            )
        ''')
        
        # Cart Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cart (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                buyer_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                FOREIGN KEY (buyer_id) REFERENCES buyer (id),
                FOREIGN KEY (product_id) REFERENCES product (id)
            )
        ''')
        
        # Orders Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                buyer_id INTEGER NOT NULL,
                total_amount REAL NOT NULL,
                address TEXT NOT NULL,
                payment_method TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (buyer_id) REFERENCES buyer (id)
            )
        ''')
        
        # Reviews Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                buyer_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                rating INTEGER NOT NULL,
                review TEXT NOT NULL,
                FOREIGN KEY (buyer_id) REFERENCES buyer (id),
                FOREIGN KEY (product_id) REFERENCES product (id)
            )
        ''')
        
        db.commit()

init_db()

# ====================================================
# Helper Functions & Decorators
# ====================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'role' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in allowed_roles:
                flash('Unauthorized access.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ====================================================
# Home & Authentication Routes
# ====================================================

@app.route('/')
def home():
    db = get_db()
    products = db.execute('SELECT * FROM product').fetchall()
    return render_template('home.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('role', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not role or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('login'))

        # Hardcoded Admin Login
        if role == 'admin':
            if email == 'admin@gmail.com' and password == 'admin123':
                session['user_id'] = 0
                session['role'] = 'admin'
                session['user_name'] = 'Administrator'
                flash('Welcome Admin!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid Admin Credentials.', 'danger')
                return redirect(url_for('login'))

        db = get_db()
        if role == 'seller':
            seller = db.execute('SELECT * FROM seller WHERE email = ?', (email,)).fetchone()
            if seller and check_password_hash(seller['password'], password):
                session['user_id'] = seller['id']
                session['role'] = 'seller'
                session['user_name'] = seller['seller_name']
                flash('Logged in successfully as Seller!', 'success')
                return redirect(url_for('seller_dashboard'))
            else:
                flash('Invalid Seller Credentials.', 'danger')
                return redirect(url_for('login'))

        elif role == 'buyer':
            buyer = db.execute('SELECT * FROM buyer WHERE email = ?', (email,)).fetchone()
            if buyer and check_password_hash(buyer['password'], password):
                session['user_id'] = buyer['id']
                session['role'] = 'buyer'
                session['user_name'] = buyer['buyer_name']
                flash('Logged in successfully as Buyer!', 'success')
                return redirect(url_for('buyer_dashboard'))
            else:
                flash('Invalid Buyer Credentials.', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Invalid Role Selected.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register_seller', methods=['GET', 'POST'])
def register_seller():
    if request.method == 'POST':
        seller_name = request.form.get('seller_name', '').strip()
        contact = request.form.get('contact', '').strip()
        address = request.form.get('address', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not seller_name or not contact or not address or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register_seller'))

        db = get_db()
        existing = db.execute('SELECT id FROM seller WHERE email = ?', (email,)).fetchone()
        if existing:
            flash('Email already registered as Seller.', 'danger')
            return redirect(url_for('register_seller'))

        hashed_pw = generate_password_hash(password)
        db.execute(
            'INSERT INTO seller (seller_name, contact, address, email, password) VALUES (?, ?, ?, ?, ?)',
            (seller_name, contact, address, email, hashed_pw)
        )
        db.commit()
        flash('Seller Registration Successful! Please Login.', 'success')
        return redirect(url_for('login'))

    return render_template('register_seller.html')

@app.route('/register_buyer', methods=['GET', 'POST'])
def register_buyer():
    if request.method == 'POST':
        buyer_name = request.form.get('buyer_name', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not buyer_name or not phone or not address or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register_buyer'))

        db = get_db()
        existing = db.execute('SELECT id FROM buyer WHERE email = ?', (email,)).fetchone()
        if existing:
            flash('Email already registered as Buyer.', 'danger')
            return redirect(url_for('register_buyer'))

        hashed_pw = generate_password_hash(password)
        db.execute(
            'INSERT INTO buyer (buyer_name, phone, address, email, password) VALUES (?, ?, ?, ?, ?)',
            (buyer_name, phone, address, email, hashed_pw)
        )
        db.commit()
        flash('Buyer Registration Successful! Please Login.', 'success')
        return redirect(url_for('login'))

    return render_template('register_buyer.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# ====================================================
# Admin Routes
# ====================================================

@app.route('/admin_dashboard')
@login_required
@role_required(['admin'])
def admin_dashboard():
    db = get_db()
    total_sellers = db.execute('SELECT COUNT(*) FROM seller').fetchone()[0]
    total_buyers = db.execute('SELECT COUNT(*) FROM buyer').fetchone()[0]
    total_products = db.execute('SELECT COUNT(*) FROM product').fetchone()[0]
    total_orders = db.execute('SELECT COUNT(*) FROM orders').fetchone()[0]

    return render_template(
        'admin_dashboard.html',
        total_sellers=total_sellers,
        total_buyers=total_buyers,
        total_products=total_products,
        total_orders=total_orders
    )

@app.route('/analytics')
@login_required
@role_required(['admin'])
def analytics():
    db = get_db()
    total_sellers = db.execute('SELECT COUNT(*) FROM seller').fetchone()[0]
    total_buyers = db.execute('SELECT COUNT(*) FROM buyer').fetchone()[0]
    total_products = db.execute('SELECT COUNT(*) FROM product').fetchone()[0]
    total_orders = db.execute('SELECT COUNT(*) FROM orders').fetchone()[0]

    return render_template(
        'analytics.html',
        total_sellers=total_sellers,
        total_buyers=total_buyers,
        total_products=total_products,
        total_orders=total_orders
    )

# ====================================================
# Seller Routes
# ====================================================

@app.route('/seller_dashboard')
@login_required
@role_required(['seller'])
def seller_dashboard():
    db = get_db()
    seller_id = session['user_id']
    total_products = db.execute('SELECT COUNT(*) FROM product WHERE seller_id = ?', (seller_id,)).fetchone()[0]
    total_buyers = db.execute('SELECT COUNT(*) FROM buyer').fetchone()[0]

    return render_template(
        'seller_dashboard.html',
        seller_name=session.get('user_name', 'Seller'),
        total_products=total_products,
        total_buyers=total_buyers
    )

@app.route('/products')
@login_required
@role_required(['seller', 'admin'])
def products():
    db = get_db()
    search = request.args.get('search', '').strip()

    if session['role'] == 'seller':
        if search:
            products_list = db.execute(
                'SELECT * FROM product WHERE seller_id = ? AND product_name LIKE ?',
                (session['user_id'], f'%{search}%')
            ).fetchall()
        else:
            products_list = db.execute(
                'SELECT * FROM product WHERE seller_id = ?',
                (session['user_id'],)
            ).fetchall()
    else:
        # Admin viewing products
        if search:
            products_list = db.execute(
                'SELECT * FROM product WHERE product_name LIKE ?',
                (f'%{search}%',)
            ).fetchall()
        else:
            products_list = db.execute('SELECT * FROM product').fetchall()

    return render_template('products.html', products=products_list, search=search)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
@role_required(['seller'])
def add_product():
    if request.method == 'POST':
        product_name = request.form.get('product_name', '').strip()
        price = request.form.get('price', '').strip()
        description = request.form.get('description', '').strip()
        color = request.form.get('color', '').strip()
        size = request.form.get('size', '').strip()
        rating = request.form.get('rating', '').strip()

        if not product_name or not price or not description or not color or not size or not rating:
            flash('All product fields are required.', 'danger')
            return redirect(url_for('add_product'))

        db = get_db()
        db.execute(
            '''INSERT INTO product (seller_id, product_name, price, description, color, size, rating)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (session['user_id'], product_name, float(price), description, color, size, int(rating))
        )
        db.commit()
        flash('Product added successfully!', 'success')
        return redirect(url_for('products'))

    return render_template('add_product.html')

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
@role_required(['seller'])
def edit_product(product_id):
    db = get_db()
    product = db.execute(
        'SELECT * FROM product WHERE id = ? AND seller_id = ?',
        (product_id, session['user_id'])
    ).fetchone()

    if not product:
        flash('Product not found or access denied.', 'danger')
        return redirect(url_for('products'))

    if request.method == 'POST':
        product_name = request.form.get('product_name', '').strip()
        price = request.form.get('price', '').strip()
        description = request.form.get('description', '').strip()
        color = request.form.get('color', '').strip()
        size = request.form.get('size', '').strip()
        rating = request.form.get('rating', '').strip()

        if not product_name or not price or not description or not color or not size or not rating:
            flash('All fields are required.', 'danger')
            return redirect(url_for('edit_product', product_id=product_id))

        db.execute(
            '''UPDATE product SET product_name = ?, price = ?, description = ?, color = ?, size = ?, rating = ?
               WHERE id = ? AND seller_id = ?''',
            (product_name, float(price), description, color, size, int(rating), product_id, session['user_id'])
        )
        db.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('products'))

    return render_template('edit_product.html', product=product)

@app.route('/delete_product/<int:product_id>')
@login_required
@role_required(['seller', 'admin'])
def delete_product(product_id):
    db = get_db()
    if session['role'] == 'seller':
        db.execute('DELETE FROM product WHERE id = ? AND seller_id = ?', (product_id, session['user_id']))
    else:
        db.execute('DELETE FROM product WHERE id = ?', (product_id,))
    db.commit()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('products'))

# ====================================================
# Buyer Routes
# ====================================================

@app.route('/buyer_dashboard')
@login_required
@role_required(['buyer'])
def buyer_dashboard():
    db = get_db()
    search = request.args.get('search', '').strip()

    if search:
        products_list = db.execute(
            'SELECT * FROM product WHERE product_name LIKE ?',
            (f'%{search}%',)
        ).fetchall()
    else:
        products_list = db.execute('SELECT * FROM product').fetchall()

    return render_template(
        'buyer_dashboard.html',
        buyer_name=session.get('user_name', 'Buyer'),
        products=products_list,
        search=search
    )

# ====================================================
# Cart Routes
# ====================================================

@app.route('/cart')
@login_required
@role_required(['buyer'])
def cart():
    db = get_db()
    buyer_id = session['user_id']
    raw_cart_items = db.execute(
        '''SELECT c.id as cart_id, c.product_id, c.quantity, p.product_name, p.price
           FROM cart c
           JOIN product p ON c.product_id = p.id
           WHERE c.buyer_id = ?''',
        (buyer_id,)
    ).fetchall()

    cart_items = []
    grand_total = 0.0

    for item in raw_cart_items:
        item_total = item['price'] * item['quantity']
        grand_total += item_total
        cart_items.append({
            'cart_id': item['cart_id'],
            'product_id': item['product_id'],
            'product_name': item['product_name'],
            'price': item['price'],
            'quantity': item['quantity'],
            'total': item_total
        })

    return render_template('cart.html', cart_items=cart_items, grand_total=grand_total)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
@role_required(['buyer'])
def add_to_cart(product_id):
    quantity = int(request.form.get('quantity', 1))
    buyer_id = session['user_id']
    db = get_db()

    existing_item = db.execute(
        'SELECT id, quantity FROM cart WHERE buyer_id = ? AND product_id = ?',
        (buyer_id, product_id)
    ).fetchone()

    if existing_item:
        new_quantity = existing_item['quantity'] + quantity
        db.execute('UPDATE cart SET quantity = ? WHERE id = ?', (new_quantity, existing_item['id']))
    else:
        db.execute(
            'INSERT INTO cart (buyer_id, product_id, quantity) VALUES (?, ?, ?)',
            (buyer_id, product_id, quantity)
        )

    db.commit()
    flash('Item added to cart!', 'success')
    return redirect(url_for('buyer_dashboard'))

@app.route('/update_cart/<int:cart_id>', methods=['POST'])
@login_required
@role_required(['buyer'])
def update_cart(cart_id):
    quantity = int(request.form.get('quantity', 1))
    db = get_db()

    if quantity > 0:
        db.execute(
            'UPDATE cart SET quantity = ? WHERE id = ? AND buyer_id = ?',
            (quantity, cart_id, session['user_id'])
        )
    else:
        db.execute('DELETE FROM cart WHERE id = ? AND buyer_id = ?', (cart_id, session['user_id']))

    db.commit()
    flash('Cart updated!', 'success')
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:cart_id>')
@login_required
@role_required(['buyer'])
def remove_from_cart(cart_id):
    db = get_db()
    db.execute('DELETE FROM cart WHERE id = ? AND buyer_id = ?', (cart_id, session['user_id']))
    db.commit()
    flash('Item removed from cart!', 'success')
    return redirect(url_for('cart'))

# ====================================================
# Checkout Routes
# ====================================================

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
@role_required(['buyer'])
def checkout():
    db = get_db()
    buyer_id = session['user_id']

    buyer = db.execute('SELECT * FROM buyer WHERE id = ?', (buyer_id,)).fetchone()
    raw_cart_items = db.execute(
        '''SELECT c.id as cart_id, c.product_id, c.quantity, p.product_name, p.price
           FROM cart c
           JOIN product p ON c.product_id = p.id
           WHERE c.buyer_id = ?''',
        (buyer_id,)
    ).fetchall()

    if not raw_cart_items:
        flash('Your cart is empty!', 'warning')
        return redirect(url_for('buyer_dashboard'))

    cart_items = []
    grand_total = 0.0
    for item in raw_cart_items:
        item_total = item['price'] * item['quantity']
        grand_total += item_total
        cart_items.append({
            'product_name': item['product_name'],
            'price': item['price'],
            'quantity': item['quantity'],
            'total': item_total
        })

    if request.method == 'POST':
        address = request.form.get('address', buyer['address']).strip()
        payment_method = request.form.get('payment_method', '').strip()

        if not payment_method:
            flash('Please select a payment method.', 'danger')
            return redirect(url_for('checkout'))

        # Store order
        db.execute(
            'INSERT INTO orders (buyer_id, total_amount, address, payment_method) VALUES (?, ?, ?, ?)',
            (buyer_id, grand_total, address, payment_method)
        )

        # Clear Cart
        db.execute('DELETE FROM cart WHERE buyer_id = ?', (buyer_id,))
        db.commit()

        flash('Order placed successfully!', 'success')
        return redirect(url_for('buyer_dashboard'))

    return render_template(
        'checkout.html',
        buyer=buyer,
        cart_items=cart_items,
        grand_total=grand_total
    )

# ====================================================
# Review Routes
# ====================================================

@app.route('/reviews', methods=['GET', 'POST'])
@login_required
def reviews():
    db = get_db()

    if request.method == 'POST':
        if session['role'] != 'buyer':
            flash('Only buyers can submit reviews.', 'danger')
            return redirect(url_for('reviews'))

        product_id = request.form.get('product_id', '').strip()
        rating = request.form.get('rating', '').strip()
        review = request.form.get('review', '').strip()

        if not product_id or not rating or not review:
            flash('All fields are required to post a review.', 'danger')
            return redirect(url_for('reviews'))

        db.execute(
            'INSERT INTO reviews (buyer_id, product_id, rating, review) VALUES (?, ?, ?, ?)',
            (session['user_id'], int(product_id), int(rating), review)
        )
        db.commit()
        flash('Review submitted successfully!', 'success')
        return redirect(url_for('reviews'))

    products_list = db.execute('SELECT id, product_name FROM product').fetchall()
    
    reviews_list = db.execute(
        '''SELECT r.id, r.rating, r.review, r.buyer_id, b.buyer_name, p.product_name
           FROM reviews r
           JOIN buyer b ON r.buyer_id = b.id
           JOIN product p ON r.product_id = p.id
           ORDER BY r.id DESC'''
    ).fetchall()

    return render_template('reviews.html', products=products_list, reviews=reviews_list)

@app.route('/edit_review/<int:review_id>', methods=['GET', 'POST'])
@login_required
@role_required(['buyer'])
def edit_review(review_id):
    db = get_db()
    review_item = db.execute(
        'SELECT * FROM reviews WHERE id = ? AND buyer_id = ?',
        (review_id, session['user_id'])
    ).fetchone()

    if not review_item:
        flash('Review not found or access denied.', 'danger')
        return redirect(url_for('reviews'))

    if request.method == 'POST':
        rating = request.form.get('rating', '').strip()
        review = request.form.get('review', '').strip()

        if not rating or not review:
            flash('Rating and Review text are required.', 'danger')
            return redirect(url_for('edit_review', review_id=review_id))

        db.execute(
            'UPDATE reviews SET rating = ?, review = ? WHERE id = ? AND buyer_id = ?',
            (int(rating), review, review_id, session['user_id'])
        )
        db.commit()
        flash('Review updated successfully!', 'success')
        return redirect(url_for('reviews'))

    return render_template('edit_review.html', review=review_item)

@app.route('/delete_review/<int:review_id>')
@login_required
def delete_review(review_id):
    db = get_db()
    if session['role'] == 'buyer':
        db.execute('DELETE FROM reviews WHERE id = ? AND buyer_id = ?', (review_id, session['user_id']))
    elif session['role'] == 'admin':
        db.execute('DELETE FROM reviews WHERE id = ?', (review_id,))
    else:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('reviews'))

    db.commit()
    flash('Review deleted successfully!', 'success')
    return redirect(url_for('reviews'))

# ====================================================
# Main Execution
# ====================================================

if __name__ == '__main__':
    app.run(debug=True)