<?php

namespace App\Http\Controllers;

use App\Mail\Contact;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Support\Facades\log;
use Illuminate\Support\Facades\Mail;

class UserController extends Controller
{
        public function authenticate(Request $request)
        {
                $credentials = $request->only('email', 'password');
                try {
                        if (!$token = JWTAuth::attempt($credentials)) {
                                $user = User::where('email', $credentials['email'])->first();
                                if (date('H') < $user->temps && $user->temps != null) {
                                        return response()->json(['message' => 'trop de tentativeeee'], 401);
                                } else {
                                        $user->temps = null;
                                        $user->save();
                                }
                                $user->login_fails = $user->login_fails + 1;
                                $user->save();
                                $restant = $user->login_fails - 1;
                                if ($user->login_fails > 3) {

                                        log::debug('Trop de tentative, vous pourrez reessayez dans 1 heure');
                                        Mail::to($credentials['email'])->send(new Contact([
                                                'name' => $user['name'],
                                                'message' => 'Trop de tentative, vous pourrez reessayez dans 1 heure'
                                        ]));

                                        $user->login_fails = 0;
                                        $user->temps = date('H') + 2;
                                        $user->save();
                                        return response()->json(['message' => 'trop de tentative'], 401);
                                } else {
                                        return response()->json(['message' => 'tentative restant: ' . (3 - $restant)]);
                                }
                        }
                } catch (JWTException $e) {
                        return response()->json(['message' => 'could_not_create_token'], 500);
                }
                $user = User::where('email', $credentials['email'])->first();
                $user->login_fails = 0;
                $user->save();
                return response()->json(['message' => 'vous êtes connecté', 'token' => compact('token')]);
        }

        public function register(Request $request)
        {
                $validator = Validator::make(
                        $request->all(),
                        [
                                'name' => 'required|string|max:255',
                                'email' => 'required|string|email|max:255|unique:users',
                                'password' => 'required|string|min:6'
                        ],
                );

                if ($validator->fails()) {
                        return response()->json($validator->errors()->toJson(), 400);
                }

                $user = User::create([
                        'name' => $request->get('name'),
                        'email' => $request->get('email'),
                        'password' => Hash::make($request->get('password')),
                        'login_fails' => 0
                ]);

                $token = JWTAuth::fromUser($user);

                return response()->json(compact('user', 'token'), 201);
        }

        public function getAuthenticatedUser()
        {
                try {

                        if (!$user = JWTAuth::parseToken()->authenticate()) {
                                return response()->json(['user_not_found'], 404);
                        }
                } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {

                        return response()->json(['token_expired'], $e->getStatusCode());
                } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {

                        return response()->json(['token_invalid'], $e->getStatusCode());
                } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {

                        return response()->json(['token_absent'], $e->getStatusCode());
                }

                return response()->json(compact('user'));
        }
}
