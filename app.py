@app.route('/login', methods=['GET', 'POST'])
def login():
    error_msg = None
    if request.method == 'POST':
        input_user = request.form['username']
        input_pass = request.form['password']
        record = users_col.find_one({'username': input_user})
        
        if record and bcrypt.checkpw(input_pass.encode('utf-8'), record['password_hash'].encode('utf-8')):
            session['username'] = record['username']
            session['role'] = record['role']
            return redirect(url_for('index'))
        
        error_msg = 'Access Denied: Invalid Security Signature Matching'
        
    return render_template('login.html', error=error_msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        new_user = request.form['username']
        new_pass = request.form['password']
        
        existing_user = users_col.find_one({'username': new_user})
        if existing_user:
            return 'Registration Error: Username already exists!'
            
        passwd_bytes = new_pass.encode('utf-8')
        salt_hash = bcrypt.gensalt()
        hashed_value = bcrypt.hashpw(passwd_bytes, salt_hash)
        
        users_col.insert_one({
            'username': new_user,
            'password_hash': hashed_value.decode('utf-8'),
            'role': 'Operator'
        })
        return redirect(url_for('login'))
    return render_template('register.html')
