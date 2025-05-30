<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class FormSubmittedNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public $form;
    public $employee;

    public function __construct($form, $employee)
    {
        $this->form = $form;
        $this->employee = $employee;
    }

    public function via($notifiable)
    {
        return ['database', 'broadcast'];
    }

    public function toArray($notifiable)
    {
        return [
            'message' => $this->employee->name . ' a soumis le formulaire: ' . $this->form->title,
            'form_id' => $this->form->id,
            'url' => '/admin/forms/' . $this->form->id . '/submissions'
        ];
    }
}