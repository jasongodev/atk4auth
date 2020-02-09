<?php
class Providers extends \atk4\data\Model{
    public $table = 'providers';

    public function init()
    {
        parent::init();
        $this->addField('name', ['actual' => 'nicename', 'required' => true, 'type' => 'string']);
        $this->addField('sys_name', ['actual' => 'name', 'system' => true]);

        $this->addField('iso', ['caption' => 'ISO', 'required' => true, 'type' => 'string']);
        $this->addField('iso3', ['caption' => 'ISO3', 'required' => true, 'type' => 'string']);
        $this->addField('numcode', ['caption' => 'ISO Numeric Code', 'type' => 'number', 'required' => true]);
        $this->addField('phonecode', ['caption' => 'Phone Prefix', 'type' => 'number', 'required' => true]);
    }
}
?>