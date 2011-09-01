<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

/**
 * Users
 *
 * This model represents user authentication data. It operates the following tables:
 * - user account data,
 * - user profiles
 *
 * @package	Tank_auth
 * @author	Ilya Konyukhov (http://konyukhov.com/soft/)
 */
class Users extends CI_Model
{
	private $table_name			= 'users';			// user accounts
	private $profile_table_name	= 'user_profiles';	// user profiles

	function __construct()
	{
		parent::__construct();

		$ci =& get_instance();
		$this->table_name			= $ci->config->item('db_table_prefix', 'tank_auth').$this->table_name;
		$this->profile_table_name	= $ci->config->item('db_table_prefix', 'tank_auth').$this->profile_table_name;
	}

	/**
	 * Get user record by Id
	 *
	 * @param	int
	 * @param	bool
	 * @return	object
	 */
	function get_user_by_id($user_id, $activated)
	{
		$query = R::findOne($this->table_name, 'id = :id and activated = :activated', array('id' => $user_id, 'activated' => $activated));
		return $query != FALSE ? $query : NULL;
	}

	/**
	 * Get user record by login (username or email)
	 *
	 * @param	string
	 * @return	object
	 */
	function get_user_by_login($login)
	{
		$query = R::findOne($this->table_name, 'username = :username or email = :username', array('username' => strtolower($login), 'username' => strtolower($login)) );
		return $query != FALSE ? $query : NULL;
	}

	/**
	 * Get user record by username
	 *
	 * @param	string
	 * @return	object
	 */
	function get_user_by_username($username)
	{
		$query = R::findOne($this->table_name, 'username = :username', array('username' => strtolower($username)));
		return $query != FALSE ? $query : NULL;
	}

	/**
	 * Get user record by email
	 *
	 * @param	string
	 * @return	object
	 */
	function get_user_by_email($email)
	{
		$query = R::findOne($this->table_name, 'email = :email', array('email' => strtolower($email)));
		return $query != FALSE ? $query : NULL;
	}

	/**
	 * Check if username available for registering
	 *
	 * @param	string
	 * @return	bool
	 */
	function is_username_available($username)
	{
		$query = R::findOne($this->table_name, 'username = :username', array('username' => strtolower($username)));
		return $query == FALSE ? TRUE : FALSE;
	}

	/**
	 * Check if email available for registering
	 *
	 * @param	string
	 * @return	bool
	 */
	function is_email_available($email)
	{
		$query = R::findOne($this->table_name, 'email = :email or new_email = :email', array('email' => $email));
		return $query == FALSE ? TRUE : FALSE;
	}

	/**
	 * Create new user record
	 *
	 * @param	array
	 * @param	bool
	 * @return	array
	 */
	function create_user($data, $activated = TRUE)
	{
		$data['created'] = date('Y-m-d H:i:s');
		$data['activated'] = $activated ? 1 : 0;

		$user = R::dispense($this->table_name);
		$user->import($data);
		R::store($user);
		if ($activated) {
			$this->create_profile($user_id);
			return array('user_id' => $user_id);
		}
		return NULL;
	}

	/**
	 * Activate user if activation key is valid.
	 * Can be called for not activated users only.
	 *
	 * @param	int
	 * @param	string
	 * @param	bool
	 * @return	bool
	 */
	function activate_user($user_id, $activation_key, $activate_by_email)
	{
		if ($activate_by_email) {
			$query = R::findOne($this->table_name, 'id = :id and new_email_key = :key and activated = :act', array('id' => $user_id, 'key' => $activation_key, 'act' => 0));
		} else {
			$query = R::findOne($this->table_name, 'id = :id and new_password_key = :key and activated = :act', array('id' => $user_id, 'key' => $activation_key, 'act' => 0));
		}

		if ($query != FALSE) {
			$save = R::load($this->table_name, $query->id);
			$save->activated = 1;
			$save->new_email_key = NULL;
			R::store($save);
			$this->create_profile($user_id);
			return TRUE;
		}
		return FALSE;
	}

	/**
	 * Purge table of non-activated users
	 *
	 * @param	int
	 * @return	void
	 */
	function purge_na($expire_period = 172800)
	{
		$entries = R::find($this->table_name, 'activated = :act and created < :time', array('act' => 0, 'time' => time()));
		foreach ($entries as $entry) {
			R::trash($entry);
		}
	}

	/**
	 * Delete user record
	 *
	 * @param	int
	 * @return	bool
	 */
	function delete_user($user_id)
	{
		$user = R::load($this->table_name, $user_id);
		$delete = R::trash($user);
		return $delete != FALSE ? TRUE : FALSE;
	}

	/**
	 * Set new password key for user.
	 * This key can be used for authentication when resetting user's password.
	 *
	 * @param	int
	 * @param	string
	 * @return	bool
	 */
	function set_password_key($user_id, $new_pass_key)
	{
		$save = R::load($this->table_name, $user_id);
		$save->new_password_key = $new_pass_key;
		$save->new_password_requested = date('Y-m-d H:i:s');
		$saved = R::store($save);
		return $saved != FALSE ? TRUE : FALSE;
	}

	/**
	 * Check if given password key is valid and user is authenticated.
	 *
	 * @param	int
	 * @param	string
	 * @param	int
	 * @return	void
	 */
	function can_reset_password($user_id, $new_pass_key, $expire_period = 900)
	{
		$query = R::findOne($this->table_name, 'id = :id and new_password_key = :key and new_password_requested > :time', array('id' => $user_id, 'key' => $new_pass_key, 'time' => time() - $expire_period));
		return $query != FALSE ? TRUE : FALSE;
	}

	/**
	 * Change user password if password key is valid and user is authenticated.
	 *
	 * @param	int
	 * @param	string
	 * @param	string
	 * @param	int
	 * @return	bool
	 */
	function reset_password($user_id, $new_pass, $new_pass_key, $expire_period = 900)
	{
		$save = R::load($this->table_name, $user_id);
		$save->password = $new_pass;
		$save->new_password_key = NULL;
		$save->new_password_requested = NULL;
		$saved = R::store($save);
		return $saved != FALSE ? TRUE : FALSE;
	}

	/**
	 * Change user password
	 *
	 * @param	int
	 * @param	string
	 * @return	bool
	 */
	function change_password($user_id, $new_pass)
	{
		$save = R::load($this->table_name, $user_id);
		$save->password = $new_pass;
		$saved = R::store($save);
		return $saved != FALSE ? TRUE : FALSE;
	}

	/**
	 * Set new email for user (may be activated or not).
	 * The new email cannot be used for login or notification before it is activated.
	 *
	 * @param	int
	 * @param	string
	 * @param	string
	 * @param	bool
	 * @return	bool
	 */
	function set_new_email($user_id, $new_email, $new_email_key, $activated)
	{
		$save = R::load($this->table_name, $user_id);
		$activated ? $save->new_email = $new_email : $save->email = $new_email;
		$save->new_email_key = $new_email_key;
		$saved = R::store($save);
		return $saved != FALSE ? TRUE : FALSE;
	}

	/**
	 * Activate new email (replace old email with new one) if activation key is valid.
	 *
	 * @param	int
	 * @param	string
	 * @return	bool
	 */
	function activate_new_email($user_id, $new_email_key)
	{
		$save = R::load($this->table_name, $user_id);
		$save->email = $save->new_email;
		$save->new_email = NULL;
		$save->new_email_key = NULL;
		$saved = R::store($save);
		return $saved != FALSE ? TRUE : FALSE;
	}

	/**
	 * Update user login info, such as IP-address or login time, and
	 * clear previously generated (but not activated) passwords.
	 *
	 * @param	int
	 * @param	bool
	 * @param	bool
	 * @return	void
	 */
	function update_login_info($user_id, $record_ip, $record_time)
	{
		$save = R::load($this->table_name, $user_id);
		$save->new_password_key = NULL;
		$save->new_password_requested = NULL;
		if ($record_ip)		$save->last_ip = $this->input->ip_address();
		if ($record_time)	$save->last_login = date('Y-m-d H:i:s');
		R::store($save);
	}

	/**
	 * Ban user
	 *
	 * @param	int
	 * @param	string
	 * @return	void
	 */
	function ban_user($user_id, $reason = NULL)
	{
		$save = R::load($this->table_name, $user_id);
		$save->banned = 1;
		$save->ban_reason = $reason;
		R::store($save);
	}

	/**
	 * Unban user
	 *
	 * @param	int
	 * @return	void
	 */
	function unban_user($user_id)
	{
		$save = R::load($this->table_name, $user_id);
		$save->banned = 0;
		$save->ban_reason = NULL;
		R::store($save);
	}

	/**
	 * Create an empty profile for a new user
	 *
	 * @param	int
	 * @return	bool
	 */
	private function create_profile($user_id)
	{
		$save = R::dispense($this->profile_table_name);
		$save->user_id = $user_id;
		$saved = R::store($save);
		return $saved != FALSE ? TRUE : FALSE;
	}

	/**
	 * Delete user profile
	 *
	 * @param	int
	 * @return	void
	 */
	private function delete_profile($user_id)
	{
		$del = R::load($this->profile_table_name, $user_id);
		R::trash($del);
	}
}

/* End of file users.php */
/* Location: ./application/models/auth/users.php */