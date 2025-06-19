<?php
namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Notification;

class RoleUpdatedNotification extends Notification
{
    use Queueable;

    protected $message;
    protected $roles;
    protected $action;

    public function __construct($message, $roles = [], $action = '')
    {
        $this->message = $message;
        $this->roles = $roles;
        $this->action = $action;
    }

    public function toArray($notifiable)
    {
        return [
            'message' => $this->message,
            'roles' => $this->roles,
            'action' => $this->action,
        ];
    }
}
