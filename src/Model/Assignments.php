<?php
namespace sirjasongo\atk4auth\Model;

class Assignments extends \atk4\data\Model
{
    use \sirjasongo\atk4m2m\ManyToMany;
    
    public $table = 'assignments';

    public function init()
    {
        parent::init();
        $this->addBridgeBetween(User::class, Role::class);
    }
}
