<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

/**
 * User_Autologin
 *
 * This model represents user autologin data. It can be used
 * for user verification when user claims his autologin passport.
 *
 * @package	Tank_auth
 * @author	Ilya Konyukhov (http://konyukhov.com/soft/)
 */
class User_Autologin extends CI_Model
{
	private $table_name			= 'user_autologin';
	private $users_table_name	= 'users';

	function __construct()
	{
		parent::__construct();

		$ci =& get_instance();
		$this->table_name		= $ci->config->item('db_table_prefix', 'tank_auth').$this->table_name;
		$this->users_table_name	= $ci->config->item('db_table_prefix', 'tank_auth').$this->users_table_name;
	}

	/**
	 * Get user data for auto-logged in user.
	 * Return NULL if given key or user ID is invalid.
	 *
	 * @param	int
	 * @param	string
	 * @return	object
	 */
	function get($user_id, $key)
	{
		/*
		$query = R::getAll('select '.$this->users_table_name.'id, '.$this->users_table_name.'.username from '
				             .$this->users_table_name.' join '.$this->table_name.' on '.$this->table_name.'user_id = '
					     .$this->users_table_name.'id where '.$this->table_name.'.user_id = '.$user_id.' and '
					     .$this->table_name.'key_id = '.$key);
		*/
		$query = R::getAll('SELECT '.$this->users_table_name.'.id, '.$this->users_table_name.'.username from '.$this->users_table_name.' join '.$this->table_name.' on '.$this->table_name.'.user_id = '.$this->users_table_name.'.id where '.$this->table_name.'.user_id = "'.$username.'" and '.$this->table_name.'.key_id = "'.$key_id.'"');
		return $query != FALSE ? TRUE : NULL;
	}

	/**
	 * Save data for user's autologin
	 *
	 * @param	int
	 * @param	string
	 * @return	bool
	 */
	function set($user_id, $key)
	{
		$save = R::dispense($this->table_name, $user_id);
		$save->key_id = $key;
		$save->user_agent = substr($this->input->user_agent(), 0, 149);
		$save->last_ip = $this->input->ip_address();
		R::store($save);
	}

	/**
	 * Delete user's autologin data
	 *
	 * @param	int
	 * @param	string
	 * @return	void
	 */
	function delete($user_id, $key)
	{
		$del = R::load($this->table_name, $user_id);
		R::trash($del);
	}

	/**
	 * Delete all autologin data for given user
	 *
	 * @param	int
	 * @return	void
	 */
	function clear($user_id)
	{
		$del = R::load($this->table_name, $user_id);
		R::trash($del);
	}

	/**
	 * Purge autologin data for given user and login conditions
	 *
	 * @param	int
	 * @return	void
	 */
	function purge($user_id)
	{
		$del = R::findOne($this->table_name, 'user_id = :id and user_agent = :agent and last_ip = :ip', array('id' => $user_id, 'agent' => substr($this->input->user_agent(), 0, 149), 'ip' => $this->input->ip_address()));
		R::trash($del);
	}
}

/* End of file user_autologin.php */
/* Location: ./application/models/auth/user_autologin.php */