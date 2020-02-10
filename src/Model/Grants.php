<?php
namespace sirjasongo\atk4auth\Model;

class Grants extends \atk4\data\Model {
    use \sirjasongo\atk4m2m\ManyToMany;
    public $table = 'grants';

    public function init()
    {
        parent::init();
        //$this->addBridgeField('Permission', [Permission::class, 'our_field'=> 'perm_id', 'their_field'=>'id']);
        //$this->addBridgeField('Role', [Role::class, 'our_field'=> 'role_id', 'their_field'=>'id']);
        $this->addBridgeBetween(Permission::class, Role::class);
    }
}

?>