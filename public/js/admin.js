const deleteProduct = (btn) => {
    const prodId = btn.parentNode.querySelector('[name=productId]').value;
    const csrf = btn.parentNode.querySelector('[name=_csrf]').value;
    const productElement = btn.closest('article');
    
    fetch('/admin/product/' + prodId, {
        method: 'DELETE',
        headers: {
            'csrf-token': csrf
        }
    }).then(result => {
        return result.json();
    }).then(data => {
        console.log(data);
        productElement.parentNode.removeChild(productElement);
        // let cardsLength = document.getElementsByClassName('card').length;
        // console.log('length:',cardsLength);
        // if(cardsLength === 0){
        //     let para = document.createElement("H1");
        //     let node = document.createTextNode("No products Found!");
        //     para.appendChild(node);
        //     var element = document.getElementById("main");
        //     element.appendChild(para);
        // }
    }).catch(err => {
        console.log(err);
    });
    
}