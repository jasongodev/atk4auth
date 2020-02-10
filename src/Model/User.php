<?php
namespace sirjasongo\atk4auth\Model;

class User extends \atk4\data\Model
{
    use \sirjasongo\atk4m2m\ManyToMany;
    public $table = 'users';
    const our_field = 'id';
    const their_field = ['user_id', Assignments::class=>'user_id'];

    public function init()
    {
        parent::init();

        $this->addField('email', ['required' => true, 'type' => 'string']);
        $this->addField('password', ['required' => true, 'type' => 'string']);
        $this->addField('enable_2fa', ['type' => 'integer']);
        $this->addField('totp_secret', ['type' => 'string']);

        $this->hasManyToMany(Role::class, Assignments::class, 'name');
    }

    /* public function hasRole($role)
    {
        return $this->is($role);
    }

    public function is($role)
    {
        return $this->roles->addCondition('name', $role)->action('count')->getOne();
    }

    public function hasPermission($permission)
    {
        return $this->can($permission);
    }

    public function can($permission)
    {
        return $this->permissions->addCondition('name', $permission)->action('count')->getOne();
    }*/
}
