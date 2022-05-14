<?php

namespace App\Http\Controllers\Api\Auth;

use App\Models\User;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class ResetPasswordController extends Controller
{
    public function sendResetPasswordLink(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email'
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'message' => $validator->errors(),
                ], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            $user = User::where('email', $request->email)->first();

            if (!$user) {
                return response()->json([
                    'message' => 'Incorrect email.',
                ], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            $sendResetLinkStatus = Password::sendResetLink($request->only('email'));

            if ($sendResetLinkStatus === Password::RESET_LINK_SENT) {
                return response()->json([
                    'message' => 'Reset password link has been sent.',
                ], Response::HTTP_OK);
            }

            return response()->json([
                'message' => 'Reset password link has been failed to send.'
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        } catch (\Exception $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function resetPassword(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'token' => 'required',
                'email' => 'required|email',
                'password' => 'required|min:6|confirmed'
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'message' => $validator->errors(),
                ], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            $passwordResetStatus = Password::reset(
                $request->only([
                    'email',
                    'password',
                    'password_confirmation',
                    'token'
                ]),
                function ($user, $password) {
                    $user->forceFill([
                        'password' => Hash::make($password)
                    ])->setRememberToken(Str::random(60));

                    $user->save();

                    event(new PasswordReset($user));
                }
            );

            if ($passwordResetStatus === Password::PASSWORD_RESET) {
                return response()->json([
                    'message' => 'Password has been reset.'
                ], Response::HTTP_CREATED);
            }

            return response()->json([
                'message' => 'Invalid tokn given.'
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        } catch (\Exception $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
