<?php

namespace App\Http\Controllers\Api\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class LoginController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:sanctum')->only('logout');
    }

    public function login(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required'
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'message' => $validator->errors(),
                ], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            $user = User::where('email', $request->email)->first();

            if (!$user || !Hash::check($request->password, $user->password)) {
                return response()->json([
                    'message' => 'Incorrect email or password',
                ], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            return response()->json([
                'data' => [
                    'user' => $user,
                    'access_token' => $user->createToken($request->email)->plainTextToken
                ],
                'message' => 'Token has been crated.',
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function logout(Request $request)
    {
        try {
            // Revoke all tokens ...
            // $user->tokens()->delete();

            // Revoke the token that was used to authenticate the current request ...
            $request->user()->currentAccessToken()->delete();

            // Revoke a specific token ...
            // $request->tokens()->where('id', $tokenId)->delete();

            return response()->json([
                'message' => 'All token has been revoked from this user.',
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
