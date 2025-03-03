function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  
  // Simple validation
  if (!username || !password) {
    alert('Please enter both username and password');
    return;
  }
  
  console.log('Sending login request for:', username);
  
  // Send login request to server
  fetch('https://fido-kokukuma.jp.ngrok.io/api/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username: username,
      password: password
    })
  })
  .then(response => {
    console.log('Response status:', response.status);
    // Always try to parse response as JSON, even on error
    return response.json().then(data => {
      if (!response.ok) {
        console.log('Error response:', data);
        throw new Error(data.message || 'Login failed');
      }
      return data;
    });
  })
  .then(data => {
    if (data.success) {
      document.getElementById('login-form').style.display = 'none';
      document.getElementById('success-page').style.display = 'block';
    } else {
      alert('Invalid username or password');
    }
  })
  .catch(error => {
    console.error('Login error:', error);
    alert('Error: ' + error.message);
  });
}

function logout() {
  document.getElementById('username').value = '';
  document.getElementById('password').value = '';
  document.getElementById('login-form').style.display = 'block';
  document.getElementById('success-page').style.display = 'none';
}
