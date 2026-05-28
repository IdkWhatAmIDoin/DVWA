<?php

if( isset( $_GET[ 'Change' ] ) ) {
	// Check Anti-CSRF token
	checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

	// Get input
	$pass_curr = $_GET[ 'password_current' ];
	$pass_new  = $_GET[ 'password_new' ];
	$pass_conf = $_GET[ 'password_conf' ];

	// Sanitise current password input
	$pass_curr = stripslashes( $pass_curr );

	// Check that the current password is correct
	$data = $db->prepare( 'SELECT password FROM users WHERE user = (:user) LIMIT 1;' );
	$current_user = dvwaCurrentUser();
	$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
	$data->execute();
	$row = $data->fetch();

	// Do both new passwords match and does the current password match the user?
	if( ( $pass_new == $pass_conf ) && $row && password_verify( $pass_curr, $row['password'] ) ) {
		// It does!
		$pass_new = stripslashes( $pass_new );
		$pass_new = password_hash( $pass_new, PASSWORD_BCRYPT );

		// Update database with new password
		$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
		$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
		$current_user = dvwaCurrentUser();
		$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
		$data->execute();

		// Feedback for the user
		$html .= "<pre>Password Changed.</pre>";
	}
	else {
		// Issue with passwords matching
		$html .= "<pre>Passwords did not match or current password incorrect.</pre>";
	}
}
// Generate Anti-CSRF token
generateSessionToken();

?>