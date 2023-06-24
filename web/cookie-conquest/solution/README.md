The attacker must first notice a cookie has been set to their session in the form:
```
is_admin:false
```

Trying to access the admin.php page redirects the user to an access denied page.

Manipulating the cookie to the following value allows access to the admin page disclosing the flag
```
is_admin:true
```

