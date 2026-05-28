<?php

if( isset( $_POST[ 'Change' ] ) ) {
	// Check Anti-CSRF token
	checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

	// Hide the CAPTCHA form
	$hide_form = true;

	// Get input
	$pass_new  = $_POST[ 'password_new' ];
	$pass_new  = stripslashes( $pass_new );

	$pass_conf = $_POST[ 'password_conf' ];
	$pass_conf = stripslashes( $pass_conf );


	$pass_curr = $_POST[ 'password_current' ];
	$pass_curr = stripslashes( $pass_curr );

	// Check CAPTCHA from 3rd party
	$resp = recaptcha_check_answer(
		$_DVWA[ 'recaptcha_private_key' ],
		$_POST['g-recaptcha-response']
	);

	// Did the CAPTCHA fail?
	if( !$resp ) {
		// What happens when the CAPTCHA was entered incorrectly
		$html .= "<pre><br />The CAPTCHA was incorrect. Please try again.</pre>";
		$hide_form = false;
	}
	else {
        // Check that the current password is correct
        $data = $db->prepare( 'SELECT password FROM users WHERE user = (:user) LIMIT 1;' );
        $data->bindParam( ':user', dvwaCurrentUser(), PDO::PARAM_STR );
        $data->execute();
        $row = $data->fetch();

        // Do both new password match and was the current password correct?
        if( ( $pass_new == $pass_conf ) && $row && password_verify( $pass_curr, $row['password'] ) ) {
			// Hash the new password
			$pass_new  = password_hash( $pass_new, PASSWORD_BCRYPT );

			// Update the database
            $data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
            $data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
            $data->bindParam( ':user', dvwaCurrentUser(), PDO::PARAM_STR );
            $data->execute();

            // Feedback for the end user - success!
            $html .= "<pre>Password Changed.</pre>";
        }
        else {
            // Feedback for the end user - failed!
            $html .= "<pre>Either your current password is incorrect or the new passwords did not match.<br />Please try again.</pre>";
            $hide_form = false;
        }
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?>
