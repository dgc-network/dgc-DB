// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use crypto::digest::Digest;
use crypto::sha2::Sha512;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;

use grid_sdk::protocol::pike::state::{Agent, AgentList};
use grid_sdk::protocol::pike::state::{Organization, OrganizationList};
use grid_sdk::protocol::product::state::{Product, ProductList, ProductListBuilder};
use grid_sdk::protocol::schema::state::{Schema, SchemaList, SchemaListBuilder};
use grid_sdk::protos::{FromBytes, IntoBytes};

use crate::error::RestApiResponseError;

const GRID_ADDRESS_LEN: usize = 70;
const GS1_NAMESPACE: &str = "01"; // Indicates GS1 standard
const PRODUCT_NAMESPACE: &str = "02"; // Indicates product under GS1 standard
//const GRID_NAMESPACE: &str = "621dee"; // Grid prefix
pub const GRID_NAMESPACE: &str = "621dee";
pub const GRID_SCHEMA_NAMESPACE: &str = "01";

//pub const PIKE_NAMESPACE: &str = "cad11d";
pub const PIKE_AGENT_NAMESPACE: &str = "00";
pub const PIKE_ORG_NAMESPACE: &str = "01";

pub const PIKE_NAMESPACE: &str = "cad11d";
pub const PIKE_FAMILY_NAME: &str = "pike";
pub const PIKE_FAMILY_VERSION: &str = "0.1";

pub fn get_product_prefix() -> String {
    GRID_NAMESPACE.to_string()
}

pub fn hash(to_hash: &str, num: usize) -> String {
    let mut sha = Sha512::new();
    sha.input_str(to_hash);
    let temp = sha.result_str();
    let hash = temp.get(..num).expect("PANIC! Hashing Out of Bounds Error");
    hash.to_string()
}

pub fn make_product_address(product_id: &str) -> String {
    let grid_product_gs1_prefix = get_product_prefix() + PRODUCT_NAMESPACE + GS1_NAMESPACE;
    let grid_product_gs1_prefix_len = grid_product_gs1_prefix.chars().count();
    let hash_len = GRID_ADDRESS_LEN - grid_product_gs1_prefix_len;

    grid_product_gs1_prefix + &hash(product_id, hash_len)
}

/// Computes the address a Pike Agent is stored at based on its public_key
pub fn compute_agent_address(public_key: &str) -> String {
    let mut sha = Sha512::new();
    sha.input(public_key.as_bytes());

    String::from(PIKE_NAMESPACE) + PIKE_AGENT_NAMESPACE + &sha.result_str()[..62].to_string()
}

/// Computes the address a Pike Organization is stored at based on its identifier
pub fn compute_org_address(identifier: &str) -> String {
    let mut sha = Sha512::new();
    sha.input(identifier.as_bytes());

    String::from(PIKE_NAMESPACE) + PIKE_ORG_NAMESPACE + &sha.result_str()[..62]
}

/// Computes the address a Grid Schema is stored at based on its name
pub fn compute_schema_address(name: &str) -> String {
    let mut sha = Sha512::new();
    sha.input(name.as_bytes());

    String::from(GRID_NAMESPACE) + GRID_SCHEMA_NAMESPACE + &sha.result_str()[..62].to_string()
}

/// GridSchemaState is in charge of handling getting and setting state.
pub struct ApiState<'a> {
    context: &'a dyn TransactionContext,
}

impl<'a> ApiState<'a> {
    pub fn new(context: &'a dyn TransactionContext) -> ApiState {
        ApiState { context }
    }

    pub fn get_organization(&self, id: &str) -> Result<Option<Organization>, ApplyError> {
        let address = compute_org_address(id);
        let d = self.context.get_state_entry(&address)?;
        match d {
            Some(packed) => {
                let orgs: OrganizationList = match OrganizationList::from_bytes(packed.as_slice()) {
                    Ok(orgs) => orgs,
                    Err(err) => {
                        return Err(ApplyError::InternalError(format!(
                            "Cannot deserialize organization list: {:?}",
                            err,
                        )))
                    }
                };

                for org in orgs.organizations() {
                    if org.org_id() == id {
                        return Ok(Some(org.clone()));
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    pub fn get_product(&self, product_id: &str) -> Result<Option<Product>, ApplyError> {
        let address = make_product_address(product_id); //product id = gtin
        let d = self.context.get_state_entry(&address)?;
        match d {
            Some(packed) => {
                let products = match ProductList::from_bytes(packed.as_slice()) {
                    Ok(products) => products,
                    Err(_) => {
                        return Err(ApplyError::InternalError(String::from(
                            "Cannot deserialize product list",
                        )));
                    }
                };

                // find the product with the correct id
                Ok(products
                    .products()
                    .iter()
                    .find(|p| p.product_id() == product_id)
                    .cloned())
            }
            None => Ok(None),
        }
    }

    /// Gets a Pike Agent. Handles retrieving the correct agent from an AgentList.
    pub fn get_agents(&self, public_key: &str) -> Result<Option<Vec<Agent>>, RestApiResponseError> {
        let address = compute_agent_address(public_key);
        let d = self.context.get_state_entry(&address)?;
        match d {
            Some(packed) => {
                let agents = match AgentList::from_bytes(packed.as_slice()) {
                    Ok(agents) => agents,
                    Err(err) => {
                        return Err(RestApiResponseError::NotFoundError(format!(
                            "Cannot deserialize agent list: {:?}",
                            err,
                        )));
                    }
                };
                return Ok(Some(agents.agents().to_vec()));
            }
            None => Ok(None),
        }
    }

    /// Gets a Pike Agent. Handles retrieving the correct agent from an AgentList.
    //pub fn get_agent(&self, public_key: &str) -> Result<Option<Agent>, ApplyError> {
    pub fn get_agent(&self, public_key: &str) -> Result<Option<Agent>, RestApiResponseError> {
        let address = compute_agent_address(public_key);
        let d = self.context.get_state_entry(&address)?;
        match d {
            Some(packed) => {
                let agents = match AgentList::from_bytes(packed.as_slice()) {
                    Ok(agents) => agents,
                    Err(err) => {
                        //return Err(ApplyError::InvalidTransaction(format!(
                        return Err(RestApiResponseError::NotFoundError(format!(
                            "Cannot deserialize agent list: {:?}",
                            err,
                        )));
                    }
                };

                // find the agent with the correct public_key
                for agent in agents.agents() {
                    if agent.public_key() == public_key {
                        return Ok(Some(agent.clone()));
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Gets a Grid Schema. Handles retrieving the correct Schema from a SchemaList
    pub fn get_schema(&self, name: &str) -> Result<Option<Schema>, ApplyError> {
        let address = compute_schema_address(name);
        let d = self.context.get_state_entry(&address)?;
        match d {
            Some(packed) => {
                let schemas = match SchemaList::from_bytes(packed.as_slice()) {
                    Ok(schemas) => schemas,
                    Err(err) => {
                        return Err(ApplyError::InvalidTransaction(format!(
                            "Cannot deserialize schema list: {:?}",
                            err,
                        )));
                    }
                };

                // find the schema with the correct name
                for schema in schemas.schemas() {
                    if schema.name() == name {
                        return Ok(Some(schema.clone()));
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Sets a Grid Schema in state. Handles creating a SchemaList if one does not already exist
    /// at the address the schema will be stored. If a SchemaList does already exist, there has
    /// been a hash collision. The Schema is stored in the SchemaList, sorted by the Schema name,
    /// and set in state.
    pub fn set_schema(&self, name: &str, new_schema: Schema) -> Result<(), ApplyError> {
        let address = compute_schema_address(name);
        let d = self.context.get_state_entry(&address)?;
        // get list of existing schemas, or an empty vec if none
        let mut schemas = match d {
            Some(packed) => match SchemaList::from_bytes(packed.as_slice()) {
                Ok(schema_list) => schema_list.schemas().to_vec(),
                Err(err) => {
                    return Err(ApplyError::InvalidTransaction(format!(
                        "Cannot deserialize schema list: {}",
                        err,
                    )));
                }
            },
            None => vec![],
        };

        // remove old schema if it exists and sort the schemas by name
        let mut index = None;
        for (count, schema) in schemas.iter().enumerate() {
            if schema.name() == name {
                index = Some(count);
                break;
            }
        }

        if let Some(x) = index {
            schemas.remove(x);
        }
        schemas.push(new_schema);
        schemas.sort_by_key(|s| s.name().to_string());

        // build new SchemaList and set in state
        let schema_list = SchemaListBuilder::new()
            .with_schemas(schemas)
            .build()
            .map_err(|_| {
                ApplyError::InvalidTransaction(String::from("Cannot build schema list"))
            })?;

        let serialized = match schema_list.into_bytes() {
            Ok(serialized) => serialized,
            Err(_) => {
                return Err(ApplyError::InvalidTransaction(String::from(
                    "Cannot serialize schema list",
                )));
            }
        };
        self.context
            .set_state_entry(address, serialized)
            .map_err(|err| ApplyError::InvalidTransaction(format!("{}", err)))?;
        Ok(())
    }
}

//#[cfg(test)]
//mod tests {
    //use super::*;

    use std::cell::RefCell;
    use std::collections::HashMap;

    //use grid_sdk::protocol::pike::state::{AgentBuilder, AgentListBuilder};
    //use grid_sdk::protocol::schema::state::{DataType, PropertyDefinitionBuilder, SchemaBuilder};
    //use sawtooth_sdk::processor::handler::{ContextError, TransactionContext};
    use sawtooth_sdk::processor::handler::ContextError;

    #[derive(Default)]
    /// A ApiTransactionContext that can be used to test GridSchemaState
    pub struct ApiTransactionContext {
        state: RefCell<HashMap<String, Vec<u8>>>,
    }

    impl TransactionContext for ApiTransactionContext {
        fn get_state_entries(
            &self,
            addresses: &[String],
        ) -> Result<Vec<(String, Vec<u8>)>, ContextError> {
            let mut results = Vec::new();
            for addr in addresses {
                let data = match self.state.borrow().get(addr) {
                    Some(data) => data.clone(),
                    None => Vec::new(),
                };
                results.push((addr.to_string(), data));
            }
            Ok(results)
        }

        fn set_state_entries(&self, entries: Vec<(String, Vec<u8>)>) -> Result<(), ContextError> {
            for (addr, data) in entries {
                self.state.borrow_mut().insert(addr, data);
            }
            Ok(())
        }

        /// this is not needed for these tests
        fn delete_state_entries(&self, _addresses: &[String]) -> Result<Vec<String>, ContextError> {
            unimplemented!()
        }

        /// this is not needed for these tests
        fn add_receipt_data(&self, _data: &[u8]) -> Result<(), ContextError> {
            unimplemented!()
        }

        /// this is not needed for these tests
        fn add_event(
            &self,
            _event_type: String,
            _attributes: Vec<(String, String)>,
            _data: &[u8],
        ) -> Result<(), ContextError> {
            unimplemented!()
        }
    }

    #[test]
    // Test that if an agent does not exist in state, None is returned
    fn test_get_agent_none() {
        let transaction_context = ApiTransactionContext::default();
        let state = GridSchemaState::new(&transaction_context);

        let result = state.get_agent("agent_public_key").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if an agent does exists in state, Some(Agent) is returned;
    fn test_get_agent_some() {
        let transaction_context = ApiTransactionContext::default();

        let builder = AgentBuilder::new();
        let agent = builder
            .with_org_id("organization".to_string())
            .with_public_key("agent_public_key".to_string())
            .with_active(true)
            .with_roles(vec!["Role".to_string()])
            .build()
            .unwrap();

        let builder = AgentListBuilder::new();
        let agent_list = builder.with_agents(vec![agent.clone()]).build().unwrap();
        let agent_bytes = agent_list.into_bytes().unwrap();
        let agent_address = compute_agent_address("agent_public_key");
        transaction_context
            .set_state_entry(agent_address, agent_bytes)
            .unwrap();

        let state = GridSchemaState::new(&transaction_context);

        let result = state.get_agent("agent_public_key").unwrap();
        assert!(result.is_some());
        let agent = result.unwrap();

        assert_eq!(agent.public_key(), "agent_public_key");
    }

    #[test]
    // 1. Test that if a schema is not in state a None is returned.
    // 2. Test that a schema can be added to state using set_state.
    // 3. Test that if a schema is in state it will be returned as Some(Schema).
    // 4. Test that a schema can be replaced
    fn test_grid_schema_state() {
        let transaction_context = ApiTransactionContext::default();
        let state = GridSchemaState::new(&transaction_context);

        let result = state.get_schema("TestSchema").unwrap();
        assert!(result.is_none());

        let builder = PropertyDefinitionBuilder::new();
        let property_definition = builder
            .with_name("TEST".to_string())
            .with_data_type(DataType::Enum)
            .with_description("Optional".to_string())
            .with_enum_options(vec![
                "One".to_string(),
                "Two".to_string(),
                "Three".to_string(),
            ])
            .build()
            .unwrap();

        let builder = SchemaBuilder::new();
        let schema = builder
            .with_name("TestSchema".to_string())
            .with_description("Test Schema".to_string())
            .with_owner("owner".to_string())
            .with_properties(vec![property_definition.clone()])
            .build()
            .unwrap();

        assert!(state.set_schema("TestSchema", schema).is_ok());
        let schema_result = state.get_schema("TestSchema").unwrap();
        assert!(schema_result.is_some());
        let schema = schema_result.unwrap();
        assert_eq!(schema.description(), "Test Schema");

        let builder = SchemaBuilder::new();
        let schema = builder
            .with_name("TestSchema".to_string())
            .with_description("New Description".to_string())
            .with_owner("owner".to_string())
            .with_properties(vec![property_definition.clone()])
            .build()
            .unwrap();

        assert!(state.set_schema("TestSchema", schema).is_ok());
        let schema_result = state.get_schema("TestSchema").unwrap();
        assert!(schema_result.is_some());
        let schema = schema_result.unwrap();
        assert_eq!(schema.description(), "New Description");
    }
//}
