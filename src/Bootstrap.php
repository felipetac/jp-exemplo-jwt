<?php
namespace MyApp;

use \Silex\Application;
use \Silex\Provider\MonologServiceProvider;
use \Silex\Provider\TwigServiceProvider;
use \Silex\Provider\SessionServiceProvider;
use \Silex\Provider\SecurityServiceProvider;
use \Silex\Provider\AssetServiceProvider;
use \Silex\Provider\DoctrineServiceProvider;
use \Symfony\Component\HttpFoundation\Request;
use \Doctrine\DBAL\Schema\Table;
use \Symfony\Component\HttpFoundation\ParameterBag;
use \Firebase\JWT\JWT;

class Bootstrap
{
    public static function run()
    {
        //Carregar variáveis do ambiente do arquivo .env
        $dotenv = new \Dotenv\Dotenv(__DIR__.'/../');
        $dotenv->load();
        
        $app = new Application();
        $app['debug'] = true;

        // Register the monolog logging service
        $app->register(
            new MonologServiceProvider(),
            array('monolog.logfile' => 'php://stderr')
        );

        // Register view rendering
        $app->register(
            new TwigServiceProvider(),
            array('twig.path' => '../web/views')
        );

        $app->register(
            new AssetServiceProvider(),
            array(
                'assets.version' => 'v1',
                'assets.version_format' => '%s?version=%s',
                'assets.named_packages' => array(
                    'css' => array(
                        'version' => 'css2',
                        'base_path' => '/stylesheets'
                    ),
                    'images' => array('base_path' => '/images')
                )
            )
        );

        $app->register(new SessionServiceProvider());

        $app['security.salt'] = $_ENV['SECRET'];

        $app['app.token_authenticator'] = function ($app) {
            return new Security\JWTGuardAuthenticator($app['security.encoder_factory']);
        };

        $app->register(
            new SecurityServiceProvider(),
            array(
                'security.firewalls' => array(
                    'login' => array(
                        'pattern' => '^/login$',
                    ),
                    'token' => array(
                        'pattern' => '^/token$',
                    ),
                    'secured' => array(
                        'guard' => array(
                            'authenticators' => array(
                                'app.token_authenticator'
                            ),
                
                            // Using more than 1 authenticator, you must specify
                            // which one is used as entry point.
                            // 'entry_point' => 'app.token_authenticator',
                        ),
                        'pattern'   => '^.*$',
                        'form'      => array(
                            'login_path' => '/login',
                            'check_path' => '/login_check'
                        ),
                        'logout'    => array(
                            'logout_path' => '/logout',
                            'invalidate_session' => true
                        ),
                        /*'users'     => array(
                            // raw password is foo
                            'admin' => array(
                                'ROLE_ADMIN',
                                '$2y$13$LjJAS9.pGAzrNCIkyULs6uA3ZX3tL.wL3aoI2ZEDHYzt97BEQM486'
                            ),
                        )*/
                        'users' => function () use ($app) {
                            return new Security\UserProvider($app['db']);
                        }
                    )
                )
            )
        );

        //Provider DBAL para usar SQLite3
        $app->register(new DoctrineServiceProvider(), array(
            'db.options' => array(
                'driver'   => 'pdo_sqlite',
                'path'     => __DIR__.'/../app.db',
            ),
        ));

        // Utilizado somente para criar a tabela inicial
        $schema = $app['db']->getSchemaManager();
        if (!$schema->tablesExist('users')) {
            $users = new Table('users');
            $users->addColumn('id', 'integer', array('unsigned' => true, 'autoincrement' => true));
            $users->setPrimaryKey(array('id'));
            $users->addColumn('username', 'string', array('length' => 32));
            $users->addUniqueIndex(array('username'));
            $users->addColumn('password', 'string', array('length' => 255));
            $users->addColumn('roles', 'string', array('length' => 255));

            $schema->createTable($users);

            $app['db']->insert('users', array(
                'username' => 'fabien',
                'password' => '$2y$13$LjJAS9.pGAzrNCIkyULs6uA3ZX3tL.wL3aoI2ZEDHYzt97BEQM486', // hash para senha 'foo'
                'roles' => 'ROLE_USER'
            ));

            $app['db']->insert('users', array(
                'username' => 'admin',
                'password' => '$2y$13$LjJAS9.pGAzrNCIkyULs6uA3ZX3tL.wL3aoI2ZEDHYzt97BEQM486', // hash para senha 'foo'
                'roles' => 'ROLE_ADMIN'
            ));
        }

        // Middleware para aceitar requests body em formato JSON
        // https://silex.symfony.com/doc/2.0/cookbook/json_request_body.html
        $app->before(function (Request $request) {
            if (0 === strpos($request->headers->get('Content-Type'), 'application/json')) {
                $data = json_decode($request->getContent(), true);
                $request->request->replace(is_array($data) ? $data : array());
            }
        });

        // Our web handlers

        $app->get(
            '/',
            function () use ($app) {
                $app['monolog']->addDebug('logging output.');
                return $app->json(["success" => true]);
            }
        );

        $app->get(
            '/login',
            function (Request $request) use ($app) {
                return $app['twig']->render(
                    'login.twig',
                    array(
                        'error'         => $app['security.last_error']($request),
                        'last_username' => $app['session']->get(
                            '_security.last_username'
                        ),
                    )
                );
            }
        )->bind(login);

        $app->post('/token', function (Request $request) use ($app) {
                $username = $request->request->get('username');
                $password = $request->request->get('password');
                $valid = false;

                //Para gerar o hash do password
                //$encoded = $app['security.default_encoder']->encodePassword($password, $app['security.salt']);

                $sql = "SELECT * FROM users WHERE username = ?";
                $user = $app['db']->fetchAssoc($sql, array($username));
                $jwt = null;
                if($user) {
                    $valid = $app['security.default_encoder']->isPasswordValid(
                        $user["password"],
                        $password,
                        $app['security.salt']
                    );     
                }

                if($valid){
                    $payload = array(
                        "username" => $user["username"],
                        "secret" => $password
                    );
                    $jwt = JWT::encode($payload, $app['security.salt']);
                }

                return $app->json(["jwt" => $jwt]);
            }
        );

        $app->get('/token', function (Request $request) use ($app) {
            try {
                $token = $request->headers->get("Authorization");
                $token = str_replace("Bearer ", "", $token);
                $decoded = (array) @JWT::decode($token, $app['security.salt'], array('HS256'));
                return $app->json($decoded);
            } catch(\Exception $e){
                return $app->json(["msg" => "Token Inválido!"]);;
            }       
        });

        $app->run();
    }
}
