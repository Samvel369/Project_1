document.getElementById('registerForm')?.addEventListener('submit', function(e) {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    
    if (password.length < 8 || !/\d/.test(password) || !/[a-zA-Z]/.test(password)) {
        e.preventDefault();
        alert('Пароль должен содержать минимум 8 символов, включая цифры и буквы');
        return false;
    }
    
    if (password !== confirmPassword) {
        e.preventDefault();
        alert('Пароли не совпадают');
        return false;
    }
    
    return true;
});