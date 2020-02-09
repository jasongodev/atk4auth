<?php
namespace sirjasongo\atk4auth\Model;
use sirjasongo\atk4auth\Traits\ManyToMany;

class Assignments extends \atk4\data\Model {
    use ManyToMany;
    public $table = 'assignments';

    public function init()
    {
        parent::init();
        $this->addBridgeBetween(User::class, Role::class);
    }
}

?>