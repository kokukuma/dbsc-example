function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  
  // Simple validation
  if (!username || !password) {
    alert('Please enter both username and password');
    return;
  }
  
  // In a real application, you would send this to a server for validation
  // For this simple example, we'll just check if username and password match
  if (username === 'admin' && password === 'password') {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('success-page').style.display = 'block';
  } else {
    alert('Invalid username or password');
  }
}

function logout() {
  document.getElementById('username').value = '';
  document.getElementById('password').value = '';
  document.getElementById('login-form').style.display = 'block';
  document.getElementById('success-page').style.display = 'none';
}