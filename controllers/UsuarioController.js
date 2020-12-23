const { Usuario } = require('../models');
const bcrypt = require('bcryptjs')
const servtoken = require('../services/token')


module.exports = {

    list : async (req, res, next) => {
        try{
            const re = await Usuario.findAll();
            res.status(200).json(re)
        } catch {
            res.status(500).json({ 'error' : 'Oops paso algo' })
            next()
        }
    },


  
    login : async (req, res, next) => {

            try {
                    const user = await Usuario.findOne( { where :  { email : req.body.email } } )
                    if(user){
                        // Evaluar contraseña
                        const contrasenhaValida = bcrypt.compareSync(req.body.password, user.password)
                    if (contrasenhaValida)
                    {
                        const token = servtoken.encode(user.id, user.rol)
                       
                        res.status(200).send({
                            auth : true,
                            tokenReturn : token,
                            user : user
                        })

                    }  else {
                        res.status(401).send({ auth: false, tokenReturn: null, reason:
                            "Invalid Password!" });
                            
                    }

                } else {
                    res.status(404).send({ 'error' : 'User Not Found' })
                }

            } 
            catch (error) {
                res.status(500).json({ 'error' : 'Oops paso algo' })
                next()
            }


        },
        add : async (req, res,next) => {

            try
            {
               req.body.password = bcrypt.hashSync(req.body.password, 10);
                const user = await Usuario.create(req.body)
                res.status(200).json(user)
               //res.send('goodbye')
            } 
            catch (error) 
            {
                res.status(500)
            }
        },

        
        update : async (req, res, next) => {

            try {
                //Busqueda del usuario
                 const user = await Usuario.findOne( { where :  { id : req.body.id } } )
                  
                  //ver si la contraseña vieja es válida
                const validPassword = bcrypt.compareSync(req.body.password, user.password)
  
                //contraseña encriptada
                 const newEncriptedPassword = req.body.newpassword? bcrypt.hashSync(req.body.newpassword) : user.password
  
                   if (validPassword){
                       const re = await Usuario.update({rol: req.body.rol, nombre: req.body.nombre, password: newEncriptedPassword, estado: req.body.estado}, {where: {email: req.body.email}});
                      res.status(200).json(re)
  
               }
                  else{
                       res.status(401).send({ auth: false, tokenReturn: null, reason:
                           "Invalid Password!" });
                   }
  
                  
           } catch (error) {
                   res.status(500).json({ 'error' : 'Oops paso algo' })
                   next(error)
               }
      
          },
  
      activate : async (req, res, next) => {
          try {
              const re = await Usuario.update({estado: 1}, {where: {id: req.body.id}});
              res.status(200).json(re)
              
          } catch (error) {
              res.status(500).json({ 'error' : 'Oops paso algo' })
              next(error)
          }
  
      },
      deactivate : async (req, res, next) => {
          try {
              const re = await Usuario.update({estado: 0}, {where: {id: req.body.id}})
              res.status(200).json(re)
  
          } catch (error) {
              res.status(500).json({ 'error' : 'Oops paso algo' })
              next(error)
          }
  
      },     
}


