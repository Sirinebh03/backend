<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class FormAccessNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public $form;

    public function __construct($form)
    {
        $this->form = $form;
    }

    public function via($notifiable)
    {
        return ['database', 'broadcast'];
    }

    public function toArray($notifiable)
    {
        return [
            'message' => 'Vous avez accès à un nouveau formulaire: ' . $this->form->title,
            'form_id' => $this->form->id,
            'url' => '/forms/' . $this->form->id
        ];
    }
}